# Linux C++ runtime library

[runtime.cpp](runtime.cpp) traces the independent Rust
[Linux runtime library](../linux_runtime/README.md). The separate exception,
TLS and static-lifetime fixtures in [../cpp](../cpp/README.md) also compile on
Linux. Exports use the C ABI; exceptions are caught inside C++.

All four Linux profiles pass the five lifecycle cases with GCC and Clang,
including both binding modes and the scalar ABI controls:

| Target | GCC / libstdc++ | Clang | Local execution |
| --- | --- | --- | --- |
| arm64 | 14.4.0 | 19.1.7 | Native arm64 Docker VM |
| amd64 | 14.4.0 | 19.1.7 | QEMU 7.0.0 on arm64 |
| loong64 | 14.2.0 | 19.1.7 | QEMU 10.0.13 on arm64 |
| ppc64le (ELFv2) | 14.2.0 | 19.1.7 | QEMU 10.0.13 on arm64 |

The profiles use glibc 2.41, GNU ld 2.44, and Go 1.26.10. Clang selects the
corresponding GCC toolchain and libstdc++; libc++ and LLVM libunwind remain
unverified. Reusable CI selects native runners for arm64/amd64 and
explicit QEMU execution for loong64/ppc64le. Physical LoongArch and PowerPC
hardware remains unverified.

The combined library checks:

- A typed exception caught through two RAII cleanup scopes.
- Eight C++ worker threads and the caller, initialized/zero TLS, actual
  128-byte TLS/storage addresses, and nine thread-local destructors.
- Later pthread cleanup observing the same retained TLS address after C++
  destruction, without accessing the destroyed C++ object.
- Numeric initializer priority, native argc/argv/environ, main-thread startup,
  and once-only function-local static construction.
- Imported glibc data, an interior pointer addend, allocation, and a C++
  comparison callback called by libc `qsort`.
- Explicit static destruction in reverse order 3/2/1, including repeat calls.

Bao provides a private DSO identity for the Linux image. Do not include the
Darwin-only `dso_handle.cpp` adapter. `platform.h` uses `__cxa_atexit` for its
exit observer because glibc's `atexit` wrapper resides in a static support
archive rather than the dynamic export table.

## Reproduce with Docker

From Bao's source root, prepare and test each architecture:

```sh
for arch in arm64 amd64; do
  docker build --platform "linux/$arch" -f testdata/toolchains/linux-cpp.Dockerfile \
    -t "bao-cpp-gcc:$arch" .
  docker build --platform "linux/$arch" -f testdata/toolchains/linux-cpp-clang.Dockerfile \
    -t "bao-cpp-clang:$arch" .
  bazel run //:verify -- -suite cpp -target "linux/$arch" \
    -cxx g++ -image "bao-cpp-gcc:$arch"
  bazel run //:verify -- -suite cpp -target "linux/$arch" \
    -cxx clang++ -image "bao-cpp-clang:$arch"
done
```

The Docker daemon must support execution of the selected architecture. The
verifier records daemon/image architecture and labels emulated runs. Image
bases and the Clang Debian snapshot are pinned in the Dockerfiles. Preparation
uses the network; compilation/execution containers use `--network none`.

For loong64 and ppc64le, the maintained cross image contains target GCC/Clang
toolchains, sysroots, Rust standard libraries, and QEMU. Run the Rust gates
before either C++ compiler, in the same image:

```sh
set -eu
docker build --platform linux/arm64 -f testdata/toolchains/linux-cross.Dockerfile \
  -t bao-cpp-cross:20261108 .
for arch in loong64 ppc64le; do
  bazel run //:verify -- -suite linux-cross -target "linux/$arch" -image bao-cpp-cross:20261108
  bazel run //:verify -- -suite bindings -target "linux/$arch" -image bao-cpp-cross:20261108
  for cxx in g++ clang++; do
    bazel run //:verify -- -suite cpp -target "linux/$arch" \
      -cxx "$cxx" -image bao-cpp-cross:20261108
  done
done
```

Source CI and the reusable release CI gate require those Rust runtime and typed
binding examples to pass before accepting either C++ compiler's result for
each cross architecture. The standalone `-suite cpp` command tests C++; it
does not substitute for the Rust gates. Cross results are QEMU execution,
not evidence of physical LoongArch or PowerPC hardware execution.
Release packaging jobs run a focused selected-CLI smoke test; they do not repeat
these full suites when the required source CI result is reused.

Each suite builds independent ordinary C++ executable controls, then fresh Bao
consumers in purego runtime-registration and DWARF-inferred assembly modes.
Consumers build with `CGO_ENABLED=0` and unavailable native compiler paths;
executables run read-only at `GOMAXPROCS=1` and `4`. Typed consumers have no
purego module dependency and their native source debug information is stripped
while unwind tables remain. Scalar C ABI controls exercise integer/FP register
exhaustion, mixed/narrow stack slots, pointers, TLS and Go scheduler progress.

Negative controls disable unwind registration, constructors, caller-thread TLS
finalization, or explicit static cleanup. Each must fail its corresponding
native/state check without a pass marker. Ordinary native controls prove that
normal C++ process exit runs the registered finalizers; a Go consumer returning
from main does not run them.

## Producer and consumer

Inside the target compiler image:

```sh
g++ -std=c++20 -O2 -g -fPIC -fno-omit-frame-pointer -pthread \
  -c examples/cpp_linux/runtime.cpp -o runtime.o
ar rcs libruntime.a runtime.o
bao build -target linux/amd64 -sysroot / -bindings dwarf \
  -symbol bao_example_run -symbol bao_example_check_finalized \
  -symbol bao_example_finalize -symbol bao_example_static_state \
  -o native libruntime.a
```

For arm64, use `-mno-outline-atomics`, add `-mtls-dialect=desc` with GCC, and
select `-target linux/arm64`. For Clang on arm64/amd64, use
`--gcc-toolchain=/usr/local -stdlib=libstdc++`. Cross Clang uses
`--target=loongarch64-linux-gnu` or `--target=powerpc64le-linux-gnu`,
`--gcc-toolchain=/usr -stdlib=libstdc++` in the cross image. The
producer needs the target GNU linker/sysroot; consumers need Go and compatible
target system libraries. No application shared library or runtime extraction
is involved.

Call `BaoExampleRun()` once on a locked OS thread, require 42, then call
`TLSFinalizeCurrentThread()`, and require `BaoExampleCheckFinalized() == 42`,
`TLSLiveBlocks() == 0`, and `TLSDestroyedBlocks() == 9`. After every native call
and worker has finished, `BaoExampleFinalize()` must return 42 and
`BaoExampleStaticState()` must return 43. Do not use the image after finalizing
its TLS/static state. Omitting `-bindings dwarf` selects runtime registration.

This is one combined, process-lifetime native image. The amd64 TLS profile is
PIC general/local dynamic TLS with ordinary SysV `__tls_get_addr` calls;
GNU2 TLSDESC, initial/local exec TLS, static musl, native IFUNC definitions,
preinit/fini arrays and arbitrary shared-library inputs are unsupported.
Linux amd64 Rust std is not covered by these C++ checks. C++ exceptions must
not cross Go frames or the exported C boundary. Go exit does not substitute for
explicit finalization, and remaining libc bookkeeping is process-lifetime.
