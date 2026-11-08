# Linux native runtime library

This crate is independent of GPUI and has no third-party Rust dependencies. It
keeps Rust's normal `std` and `panic=unwind` behavior. Its two exported C ABI
functions return 42 on success. Run `bao_example_run` once, finalize this image's
TLS on the same locked OS thread, then call `bao_example_check_finalized`.

It checks caught panics with two RAII cleanup drops, eight Rust threads with TLS
destructors, initialized and zero TLS isolation, main-thread TLS finalization,
128-byte native and TLS alignment, an interior pointer addend, imported libc data,
native allocation, a Rust comparison callback called by libc `qsort`, native
argc/argv/environ constructors in numeric priority order, and `std::env::args_os`.
An independent pthread key checks that later cleanup sees the original TLS
address and its dropped/modified state after Rust TLS destructors have run.

The separate [C++ counterpart](../cpp_linux/README.md) checks the same lifecycle
features with GCC and Clang/libstdc++ on Linux arm64, amd64, loong64 and
ppc64le. The latter two C++ CI/release legs are gated by these Rust runtime and
typed-binding examples in the same image. The amd64 C++ results do not establish
amd64 Rust std support.

The verified profiles are Linux arm64/glibc on native ARM64 hardware, and Linux
loong64/glibc and ppc64le/glibc ELFv2 through actual QEMU guest execution.
Physical LoongArch and PowerPC hardware remains unverified. Build the crate
with `cargo build --release --offline --target <Rust triple>` after installing
the target's Rust standard library. The maintainer verification supports a
macOS host with an ARM64 Linux Docker daemon:

```sh
bazel run //:verify -- -suite linux
# Cross image preparation is documented in testdata/toolchains/README.md.
bazel run //:verify -- -suite linux-cross -target linux/loong64 -image bao-linux-cross:20261108
bazel run //:verify -- -suite linux-cross -target linux/ppc64le -image bao-linux-cross:20261108
```

The Go verifier compiles this source to a static archive, invokes `bao build`
with native GNU `ld`, then builds and executes a
stock Go consumer with `CGO_ENABLED=0` and deliberately invalid native compiler
paths. Target libc/libgcc ELF metadata is used only during translation. No
application shared library is produced, extracted, or loaded at runtime.

Supply a trusted Linux static archive and the target glibc sysroot. `build`
combines archive members with the target GNU linker before translation:

```sh
bazel run //:bao -- build -target linux/arm64 -sysroot /path/to/linux-arm64-root \
  -o native -symbol bao_example_run -symbol bao_example_check_finalized libbao_linux_runtime.a
# In a Go consumer with purego v0.11.3 and this generated package:
go get github.com/ebitengine/purego@v0.11.3
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build
```

For typed adapters with no purego module dependency, pass `-bindings dwarf` to `build`
and compile optimized Rust with full debug information (`-C debuginfo=2`). Bao
infers the selected C signatures from the original archive, then strips source
debug information from its emitted native objects while keeping unwind data.
See [the binding workflow](../../README.md#function-bindings-and-native-debug-stripping) for the supported scalar types,
explicit-manifest alternative, and ABI assertion boundary. The maintained
`-suite bindings -target linux/<arch>` verifier checks both scalar C calls and
this complete Rust runtime on all three Linux profiles.

In runtime-registration mode, the generated `SymbolAddr0`/`SymbolAddr1` accessors
return addresses for `purego.RegisterFunc`; purego remains a module dependency
even if the library wraps registration in its own Go API. With `-bindings dwarf`,
call `native.BaoExampleRun()` and `native.BaoExampleCheckFinalized()` directly;
the consumer builds with `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build` without
importing or fetching purego. Ship the bundled bootstrap sources, headers and
notices with this generated package. Both modes perform a foreign-call
transition rather than calling native code on the Go goroutine stack.
See the [consumer usage](../../README.md#using-generated-go-packages) and
[developer binding modes](../../README.md#choosing-a-binding-mode) for details.

In either mode, keep the calling OS thread locked through native teardown and
`TLSFinalizeCurrentThread`. One translated native runtime image per consumer is
the verified scope. Objects are ELF inputs and the resulting executable is real
Linux ELF for the selected architecture, independent of Bao's Darwin ELF
input-container workaround.

The arm64 profile supports local TLSDESC sequences. The loong64 and ppc64le
profiles support checked general/local-dynamic TLS sequences calling the
image's native resolver; LoongArch requires LP64D with object ABI v1 and PowerPC
requires ELFv2. All three use native template storage,
glibc import metadata, weak unavailable optional function addresses as NULL,
native data-pointer fixups, numeric-priority initializer arrays, and registered
DWARF unwind chains. Only normal Go internal-link builds on the verified
Go/Rust/glibc versions are covered. Other architecture/ABI profiles, musl/static-libc builds,
other TLS access models, relocations in TLS templates, native IFUNC definitions,
preinit/fini arrays and arbitrary shared-library loading/unloading are rejected
or unverified. The translator does not select archive members; input must already
be combined with native `ld -r` internally by `build`, or supplied already combined
to `translate`. Python and a local purego checkout are not required.

The original native helper uses glibc `__cxa_thread_atexit_impl` to drain the
image's LIFO destructor list before pthread keys. Storage survives earlier POSIX
destructor passes, including Rust's thread cleanup, and is released on the final
allowed pass. Resurrecting/accessing TLS from another key after Bao's callback
on that final pass is outside the supported profile. Cross-image destructor
interleaving is unverified. Explicit finalization frees the main native TLS
block; a small NULL-target libc hook record and copied argv have process
lifetime because Go exit does not run libc's queued thread-exit callbacks.
