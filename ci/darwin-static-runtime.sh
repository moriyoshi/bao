#!/usr/bin/env bash
# Maintainer-only static runtimes for Bao's bounded Darwin C++/Rust profile.
set -euo pipefail
cd "$(dirname "$0")/.."
static_arch=${1:?usage: darwin-static-runtime.sh arm64|amd64 [install-prefix]}
case "$static_arch" in arm64) static_clang_arch=arm64;; amd64) static_clang_arch=x86_64;; *) exit 2;; esac
static_prefix=${2:-"$PWD/.work/static-runtimes/darwin-$static_arch"}
static_source=${BAO_STATIC_LLVM_SOURCE:-"$PWD/.work/static-runtimes/llvm-392dfff97d29/source"}
static_build=${BAO_STATIC_LLVM_BUILD:-"$PWD/.work/static-runtimes/llvm-392dfff97d29/build-$static_arch"}
static_revision=392dfff97d29b59d77e5cac6d4b6ef2585fe7117
mkdir -p "$(dirname "$static_source")"
if [[ ! -d $static_source/.git ]]; then
  git clone --depth 1 --filter=blob:none --sparse --branch llvmorg-23.1.5 \
    https://github.com/llvm/llvm-project.git "$static_source"
  git -C "$static_source" sparse-checkout set cmake runtimes libcxx libcxxabi \
    libunwind libc llvm/cmake llvm/include/llvm/Config llvm/utils
fi
[[ $(git -C "$static_source" rev-parse HEAD) == "$static_revision" ]]
cmake -S "$static_source/runtimes" -B "$static_build" -G 'Unix Makefiles' \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/clang \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_OSX_ARCHITECTURES="$static_clang_arch" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 -DCMAKE_OSX_SYSROOT="$(xcrun --show-sdk-path)" \
  '-DCMAKE_C_FLAGS=-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer' \
  '-DCMAKE_CXX_FLAGS=-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer' \
  '-DLLVM_ENABLE_RUNTIMES=libunwind;libcxxabi;libcxx' \
  -DLLVM_INCLUDE_TESTS=OFF -DLIBUNWIND_INCLUDE_TESTS=OFF \
  -DLIBCXXABI_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_TESTS=OFF \
  -DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXX_INCLUDE_DOCS=OFF \
  -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_SHARED=OFF \
  -DLIBUNWIND_ENABLE_SHARED=OFF -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
  -DLIBCXXABI_ENABLE_STATIC_UNWINDER=ON -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
  -DLIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY=ON \
  -DLIBCXX_HERMETIC_STATIC_LIBRARY=ON -DLIBCXXABI_HERMETIC_STATIC_LIBRARY=ON \
  -DLIBCXX_ENABLE_EXCEPTIONS=OFF -DLIBCXXABI_ENABLE_EXCEPTIONS=OFF \
  -DCMAKE_INSTALL_PREFIX="$static_prefix"
cmake --build "$static_build" --parallel "${BAO_STATIC_BUILD_JOBS:-4}"
cmake --install "$static_build"
for static_component in libcxx libcxxabi libunwind; do
  mkdir -p "$static_prefix/$static_component"
  cp "$static_source/$static_component/LICENSE.TXT" "$static_prefix/$static_component/LICENSE.TXT"
done
printf '{"llvm_commit":"%s","target":"darwin/%s","sdk_version":"%s","cpp_exceptions":false}\n' \
  "$static_revision" "$static_arch" "$(xcrun --show-sdk-version)" > "$static_prefix/bao-runtime-provenance.json"
