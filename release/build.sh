#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BAO_RELEASE_VERSION:?set the release tag}"
: "${BAO_RELEASE_COMMIT:?set the full source commit}"
: "${SOURCE_DATE_EPOCH:?set the source commit timestamp}"
bazel_bin=${BAZEL:-bazel}
bazel_cmd() {
  if [[ -n ${BAO_BAZEL_ROOT:-} ]]; then
    "$bazel_bin" "--output_user_root=$BAO_BAZEL_ROOT" "$@"
  else
    "$bazel_bin" "$@"
  fi
}
out=${1:-.work/dist}
if [[ $out != /* ]]; then out="$PWD/$out"; fi
mkdir -p .work
stage=$(mktemp -d "$PWD/.work/release-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
targets=(darwin_arm64 darwin_amd64 linux_amd64 linux_arm64 linux_loong64 linux_ppc64le)
labels=()
for target in "${targets[@]}"; do labels+=("//cmd/bao:release_$target"); done
bazel_cmd build --lockfile_mode=error --stamp --workspace_status_command=release/status.sh "${labels[@]}"
for target in "${targets[@]}"; do
  binary=$(bazel_cmd cquery --lockfile_mode=error --stamp --workspace_status_command=release/status.sh --output=files "//cmd/bao:release_$target")
  [[ -f $binary ]] || { echo "Expected one executable for $target: $binary" >&2; exit 1; }
  mkdir "$stage/$target"
  cp "$binary" "$stage/$target/bao"
done
bazel_cmd run --lockfile_mode=error //cmd/bao-release -- \
  -root "$PWD" -stage "$stage" -out "$out" -version "$BAO_RELEASE_VERSION" \
  -commit "$BAO_RELEASE_COMMIT" -epoch "$SOURCE_DATE_EPOCH"
