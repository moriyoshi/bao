#!/usr/bin/env bash
set -euo pipefail
# A tag and its branch push can start together. Wait for the trusted branch
# producer to save its result before release CI attempts the same exact key.
commit=${1:?usage: await-source.sh COMMIT DEFAULT_BRANCH}
branch=${2:?missing default branch}
repo=${GITHUB_REPOSITORY:?missing repository}
[[ $commit =~ ^[0-9a-f]{40}$ && $repo == */* ]] || exit 2
attempts=${BAO_CI_WAIT_ATTEMPTS:-540}
interval=${BAO_CI_WAIT_INTERVAL:-10}
[[ $attempts =~ ^[1-9][0-9]*$ && $interval =~ ^[0-9]+$ ]] || exit 2
missing=0
for ((i=0; i<attempts; i++)); do
  result=$(gh api --method GET "repos/$repo/actions/workflows/ci.yml/runs" \
    -f "head_sha=$commit" -f "branch=$branch" -f event=push -f per_page=100 \
    --jq '.workflow_runs | sort_by(.run_number, .run_attempt) | reverse | .[0] | if . == null then "missing" else [.head_sha, .head_branch, .status, (.conclusion // "pending"), (.id | tostring), .html_url] | @tsv end')
  if [[ $result == missing ]]; then
    missing=$((missing+1))
    if ((missing >= 3)); then
      echo 'No matching default-branch CI run; release CI will restore an exact result or execute fresh checks.'
      exit 0
    fi
  else
    IFS=$'\t' read -r sha ref status conclusion run_id url <<< "$result"
    [[ $sha == "$commit" && $ref == "$branch" && $run_id =~ ^[0-9]+$ && $url == "${GITHUB_SERVER_URL:-https://github.com}/$repo/actions/runs/$run_id" ]] || { echo 'Unexpected source CI identity' >&2; exit 1; }
    if [[ $status == completed ]]; then
      [[ $conclusion == success ]] || { echo "Source CI failed ($conclusion): $url" >&2; exit 1; }
      echo "Source CI completed: $url; release CI will validate the content-addressed results on its runners."
      exit 0
    fi
    case "$status" in queued|in_progress|waiting|pending|requested) ;; *) echo "Unexpected CI state: $status" >&2; exit 1 ;; esac
    echo "Waiting for source CI: $url ($status)"
  fi
  if ((i+1 < attempts)); then sleep "$interval"; fi
done
echo 'Timed out waiting for source CI' >&2
exit 1
