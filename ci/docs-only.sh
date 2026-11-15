#!/usr/bin/env bash
# Prints docs_only=true when a pull request changes only documentation, and
# docs_only=false otherwise. Documentation is Markdown outside testdata
# directories: no build, test, fixture or check reads it. A pull request is
# checked out as a merge commit, whose first parent is the base branch.
set -euo pipefail
repo=${BAO_CI_ROOT:-$(git rev-parse --show-toplevel)}
if [[ ${GITHUB_EVENT_NAME:-} != pull_request ]] || ! git -C "$repo" rev-parse -q --verify 'HEAD^2' >/dev/null; then
  echo docs_only=false
  exit 0
fi
changed=$(git -C "$repo" diff --no-renames --name-only 'HEAD^1' HEAD)
if [[ -z $changed ]]; then
  echo docs_only=false
  exit 0
fi
while IFS= read -r path; do
  case "/$path" in
    */testdata/*) echo docs_only=false; exit 0 ;;
    *.md) ;;
    *) echo docs_only=false; exit 0 ;;
  esac
done <<< "$changed"
echo docs_only=true
