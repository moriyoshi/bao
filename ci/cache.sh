#!/usr/bin/env bash
set -euo pipefail
command_name=${1:?usage: cache.sh fingerprint|record|validate SUITE [KEY]}
suite=${2:?missing suite}
case "$suite" in unit|darwin-arm64|darwin-amd64|linux-arm64|linux-amd64|windows-amd64|windows-arm64) ;; *) echo 'Unknown CI suite' >&2; exit 2 ;; esac
repo=${BAO_CI_ROOT:-$(git rev-parse --show-toplevel)}
# A committed tree can address a result only while tracked inputs still match it.
git -C "$repo" diff --quiet HEAD -- || { echo 'Tracked CI inputs differ from HEAD' >&2; exit 1; }
tree=$(git -C "$repo" rev-parse 'HEAD^{tree}')
# Tree identity excludes commit messages, timestamps and tag names. All tracked
# source, workflow, toolchain pins, fixtures and native blobs affect this value.
descriptor=$(printf 'bao-ci-v1\ntree=%s\nsuite=%s\nimage_os=%s\nimage_version=%s\nrunner_os=%s\nrunner_arch=%s\n' \
  "$tree" "$suite" "${ImageOS:-unknown}" "${ImageVersion:-unknown}" "${RUNNER_OS:-unknown}" "${RUNNER_ARCH:-unknown}")
if command -v sha256sum >/dev/null; then
  digest=$(printf '%s' "$descriptor" | sha256sum)
else
  digest=$(printf '%s' "$descriptor" | shasum -a 256)
fi
digest=${digest%% *}
key="bao-ci-result-v1-$suite-$digest"
result_dir=${BAO_CI_RESULT_DIR:-.work/ci-result/$suite}
result_file="$result_dir/result.txt"
case "$command_name" in
  fingerprint)
    cacheable=false
    if [[ -n ${ImageOS:-} && -n ${ImageVersion:-} && -n ${RUNNER_OS:-} && -n ${RUNNER_ARCH:-} ]]; then cacheable=true; fi
    printf 'key=%s\ntree=%s\ncacheable=%s\n' "$key" "$tree" "$cacheable"
    ;;
  record)
    [[ ${3:?missing expected key} == "$key" ]] || { echo 'CI inputs changed during execution' >&2; exit 1; }
    mkdir -p "$result_dir"
    origin="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-local/local}/actions/runs/${GITHUB_RUN_ID:-0}"
    commit=$(git -C "$repo" rev-parse HEAD)
    printf 'bao-ci-result-v1\n%s\n%s\n%s\npassed\n%s\n%s\n' "$key" "$tree" "$suite" "$origin" "$commit" > "$result_file"
    ;;
  validate)
    [[ ${3:?missing expected key} == "$key" && -f $result_file && ! -L $result_file ]] || exit 1
    [[ $(wc -c < "$result_file") -lt 4096 ]] || exit 1
    {
      IFS= read -r schema
      IFS= read -r recorded_key
      IFS= read -r recorded_tree
      IFS= read -r recorded_suite
      IFS= read -r status
      IFS= read -r origin
      IFS= read -r commit
      remainder=$(cat)
    } < "$result_file"
    [[ $schema == bao-ci-result-v1 && $recorded_key == "$key" && $recorded_tree == "$tree" && $recorded_suite == "$suite" && $status == passed && -z $remainder ]] || exit 1
    [[ $commit =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || exit 1
    prefix="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-local/local}/actions/runs/"
    [[ $origin == "$prefix"* && ${origin#"$prefix"} =~ ^[0-9]+$ ]] || exit 1
    printf 'Reusing passed %s CI for source tree %s (original run: %s)\n' "$suite" "$tree" "$origin"
    ;;
  *) echo 'Unknown CI cache operation' >&2; exit 2 ;;
esac
