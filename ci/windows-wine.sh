#!/usr/bin/env bash
# Sable-style local aid. Native Windows CI remains the authoritative gate.
set -euo pipefail
cd "$(dirname "$0")/.."
arch=${1:-amd64}
case "$arch" in amd64|arm64) ;; *) echo 'requires amd64 or arm64' >&2; exit 2 ;; esac
export RUSTUP_TOOLCHAIN=1.99.1
exec "${BAZEL:-bazel}" run //:verify -- -suite windows -target "windows/$arch" \
  -windows-runner "$PWD/ci/wine-run.sh" -windows-ar "${WINDOWS_AR:-llvm-ar}"
