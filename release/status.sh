#!/usr/bin/env bash
set -euo pipefail
# Stable keys make a new version/commit invalidate cached link actions.
: "${BAO_RELEASE_VERSION:?set the release tag}"
: "${BAO_RELEASE_COMMIT:?set the full source commit}"
printf 'STABLE_BAO_VERSION %s\nSTABLE_BAO_COMMIT %s\n' "$BAO_RELEASE_VERSION" "$BAO_RELEASE_COMMIT"
