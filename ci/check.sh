#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
suite=${1:?usage: check.sh unit|darwin-arm64|darwin-amd64|linux-arm64|linux-amd64|windows-amd64|windows-arm64}
bazel_bin=${BAZEL:-bazel}
bazel_cmd() {
  if [[ -n ${BAO_BAZEL_ROOT:-} ]]; then "$bazel_bin" "--output_user_root=$BAO_BAZEL_ROOT" "$@"; else "$bazel_bin" "$@"; fi
}
mkdir -p .work/ci-evidence
if [[ $suite != windows-* ]]; then bazel_cmd test --lockfile_mode=error --nocache_test_results //:tests; fi
case "$suite" in
  windows-amd64|windows-arm64)
    arch=${suite#windows-}
    [[ $(go env GOHOSTOS) == windows && $(go env GOHOSTARCH) == "$arch" ]] || {
      echo 'Windows CI requires a native matching Windows Go toolchain' >&2; exit 1;
    }
    rust_target=x86_64-pc-windows-gnu
    if [[ $arch == arm64 ]]; then rust_target=aarch64-pc-windows-gnullvm; fi
    rustup toolchain install 1.99.1 --profile minimal --target "$rust_target"
    export RUSTUP_TOOLCHAIN=1.99.1 CGO_ENABLED=0 GOENV=off GOTOOLCHAIN=local GOWORK=off
    [[ $(go version) == *'go1.26.10 '* ]]
    go test -count=1 ./pecoff ./bindings ./toolchain ./cmd/bao
    go test -count=1 ./cmd/bao-verify
    mkdir -p ".work/ci-evidence/$suite"
    go build -o .work/bao-windows.exe ./cmd/bao
    go build -o .work/bao-verify-windows.exe ./cmd/bao-verify
    # Pass native paths explicitly; Git Bash's implicit argument conversion is
    # not part of the Go executable's path contract.
    windows_root=$(cygpath -aw "$PWD")
    windows_bao=$(cygpath -aw "$PWD/.work/bao-windows.exe")
    windows_go=$(cygpath -aw "$(command -v go)")
    for driver in clang clang-cl msvc; do
      cc=clang; cxx=clang++
      runtime_args=()
      if [[ $driver == clang ]]; then
        : "${BAO_LLVM_MINGW:?matching LLVM-MinGW installation is required}"
        triple=x86_64-w64-mingw32
        if [[ $arch == arm64 ]]; then triple=aarch64-w64-mingw32; fi
        cc="$BAO_LLVM_MINGW/bin/$triple-clang.exe"
        cxx="$BAO_LLVM_MINGW/bin/$triple-clang++.exe"
        runtime_args=(-windows-dll-dir "$BAO_LLVM_MINGW/$triple/bin")
      fi
      if [[ $driver == msvc ]]; then cc=cl; cxx=cl; fi
      MSYS2_ARG_CONV_EXCL='*' .work/bao-verify-windows.exe -root "$windows_root" -bao "$windows_bao" -go "$windows_go" \
        -suite windows -target "windows/$arch" -windows-driver "$driver" \
        -windows-cc "$cc" -windows-cxx "$cxx" "${runtime_args[@]}" -evidence ".work/ci-evidence/$suite/$driver"
      if [[ $driver == clang ]]; then
        # Fresh Rust checks gate the static C++ lifecycle/exception profile.
        # Deliberately omit the language-runtime DLL directory for this leg.
        MSYS2_ARG_CONV_EXCL='*' .work/bao-verify-windows.exe -root "$windows_root" -bao "$windows_bao" -go "$windows_go" \
          -suite static -target "windows/$arch" -windows-driver clang \
          -windows-cc "$cc" -windows-cxx "$cxx" -static-runtime-root "$BAO_LLVM_MINGW/$triple" \
          -evidence ".work/ci-evidence/$suite/static-clang"
      fi
    done
    if [[ $arch == amd64 ]]; then
      # GitHub's x64 image carries the actual MinGW-w64 GCC toolchain.
      MSYS2_ARG_CONV_EXCL='*' .work/bao-verify-windows.exe -root "$windows_root" -bao "$windows_bao" -go "$windows_go" \
        -suite windows -target windows/amd64 -windows-driver mingw -windows-cc gcc -windows-cxx g++ \
        -evidence ".work/ci-evidence/$suite/mingw"
    fi
    ;;
  unit)
    bazel_cmd build --lockfile_mode=error //:bao //:verify //:native //cmd/bao-release
    bazel_cmd run --lockfile_mode=error //:bao -- version -json | jq -e '.built_with == .verified_go_linker'
    CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOENV=off GOPROXY=off GOSUMDB=off GOCACHE="$PWD/.work/go-build" \
      bazel_cmd run --lockfile_mode=error @rules_go//go -- vet ./...
    ;;
  darwin-arm64|darwin-amd64)
    arch=${suite#darwin-}
    rust_target=aarch64-apple-darwin
    if [[ $arch == amd64 ]]; then rust_target=x86_64-apple-darwin; fi
    rustup toolchain install 1.99.1 --profile minimal --target "$rust_target"
    export RUSTUP_TOOLCHAIN=1.99.1
    xcrun --show-sdk-version
    mkdir -p ".work/ci-evidence/$suite"
    for check in darwin tls bindings cpp; do
      bazel_cmd run --lockfile_mode=error //:verify -- -suite "$check" -target "darwin/$arch" -evidence ".work/ci-evidence/$suite/$check"
    done
    ci/darwin-static-runtime.sh "$arch" > ".work/ci-evidence/$suite/static-runtime-build.log" 2>&1
    bazel_cmd run --lockfile_mode=error //:verify -- -suite static -target "darwin/$arch" \
      -static-runtime-root "$PWD/.work/static-runtimes/darwin-$arch" -evidence ".work/ci-evidence/$suite/static"
    if [[ $arch == arm64 ]]; then
      bazel_cmd run --lockfile_mode=error //:verify -- -suite signatures -evidence ".work/ci-evidence/$suite/signatures"
      bazel_cmd run --lockfile_mode=error //:verify -- -suite bazel -bazel "$bazel_bin" -evidence ".work/ci-evidence/$suite/bazel"
    fi
    ;;
  linux-arm64|linux-amd64)
    arch=${suite#linux-}
    mkdir -p ".work/ci-evidence/$suite"
    docker build --platform "linux/$arch" -f testdata/toolchains/linux-cpp.Dockerfile -t bao-ci-cpp .
    docker build --platform "linux/$arch" -f testdata/toolchains/linux-cpp-clang.Dockerfile -t bao-ci-cpp-clang .
    bazel_cmd run --lockfile_mode=error //:verify -- -suite cpp -target "linux/$arch" -image bao-ci-cpp -cxx g++ -evidence ".work/ci-evidence/$suite/cpp-gcc"
    bazel_cmd run --lockfile_mode=error //:verify -- -suite cpp -target "linux/$arch" -image bao-ci-cpp-clang -cxx clang++ -evidence ".work/ci-evidence/$suite/cpp-clang"
    # The Rust std / cross-ISA suites keep their independently verified profiles.
    if [[ $arch == amd64 ]]; then exit 0; fi
    docker pull rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd
    bazel_cmd run --lockfile_mode=error //:verify -- -suite linux -evidence ".work/ci-evidence/$suite/runtime-arm64"
    bazel_cmd run --lockfile_mode=error //:verify -- -suite bindings -target linux/arm64 -evidence ".work/ci-evidence/$suite/bindings-arm64"
    docker build --platform linux/arm64 -f testdata/toolchains/linux-cross.Dockerfile -t bao-ci-cross .
    for arch in loong64 ppc64le; do
      bazel_cmd run --lockfile_mode=error //:verify -- -suite linux-cross -target "linux/$arch" -image bao-ci-cross -evidence ".work/ci-evidence/$suite/runtime-$arch"
      bazel_cmd run --lockfile_mode=error //:verify -- -suite bindings -target "linux/$arch" -image bao-ci-cross -evidence ".work/ci-evidence/$suite/bindings-$arch"
      # Both Rust runtime/binding gates above must pass in this same image
      # before accepting either compiler's C++ result for this architecture.
      for cxx in g++ clang++; do
        bazel_cmd run --lockfile_mode=error //:verify -- -suite cpp -target "linux/$arch" -cxx "$cxx" -image bao-ci-cross -evidence ".work/ci-evidence/$suite/cpp-$arch-$cxx"
      done
    done
    # The extended ARM-host image runs ARM64 natively and the other three
    # targets with explicit QEMU. Each static suite gates C++ on fresh Rust
    # runtime checks, then audits both binding modes for shared-runtime fallback.
    for static_arch in arm64 amd64 loong64 ppc64le; do
      bazel_cmd run --lockfile_mode=error //:verify -- -suite static -target "linux/$static_arch" -image bao-ci-cross -evidence ".work/ci-evidence/$suite/static-$static_arch"
    done
    ;;
  *) echo "Unknown suite: $suite" >&2; exit 2 ;;
esac
