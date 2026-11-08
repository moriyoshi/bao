# Darwin C++ runtime lifecycle probes

These self-contained C++20 libraries trace the behavior of the Rust
[runtime example](../rust_runtime/src/lib.rs). They focus on exceptions, RAII,
TLS, and static lifetime. On Darwin they use the system SDK/libc++ and no downloaded C++
dependencies. All exported test functions use the C ABI and return 42 on success.

| Source | Checks | Bao result for the tested compiler profile |
| --- | --- | --- |
| [unwind.cpp](unwind.cpp) | Throw through two RAII scopes and catch the typed exception inside C++ | Unsupported compact exception metadata; native C++ executable passes |
| [runtime.cpp](runtime.cpp) | Combined CoreFoundation, std::thread, TLS, initialization, exception and static destruction counterpart | Rejected on compact exception metadata before linking a Go consumer |
| [tls.cpp](tls.cpp) | Eight pthread workers, initialized/zero TLS, actual 128-byte TLS addresses, nine C++ destructors, teardown while TLS remains accessible | Passes with the producer-side DSO handle and explicit startup-thread TLS finalization |
| [static_initializers.cpp](static_initializers.cpp) | Global constructor order on the startup thread, once-only local static construction, libc exit callback | Construction passes; Go process exit does not run the libc callback |
| [static_lifetime.cpp](static_lifetime.cpp) | Compiler-generated global/local static destructors, reverse order 3/2/1, repeated explicit finalization | Passes with the producer-side handle and explicit finalization; Go process exit alone does not run it |

The verifier also builds `tls.cpp` with `BAO_CPP_TRIVIAL_TLS`, which removes the
nontrivial destructor as a diagnostic control. It exercises TLS without needing
the DSO adapter. The real destructor case uses ordinary exception-enabled C++
compilation; the supported cases do not disable exceptions to hide metadata.

`dso_handle.cpp` supplies the opaque image identity a native executable linker
normally provides. Bao and Go's internal linker do not currently supply this on Darwin
automatically. Without it, the nontrivial TLS and static-destructor fixtures
fail with `system SDK does not export ___dso_handle`. This is an explicit
producer-side adapter for one non-unloaded native image, not a general C++
loader or an automatic finalizer facility.

The normal native TLS control can report result 128 with successful destructor
counters: its Darwin TLS allocation did not meet the requested 128-byte
alignment. The fixture obscures the actual address from constant folding, so
this is not replaced by the compiler's alignment assumption. That native
control failure is recorded separately; Bao's translated TLS must actually
meet the alignment and teardown checks to pass.

## Verification

From Bao's source root on macOS:

```sh
bazel run //:verify -- -suite cpp -target darwin/arm64
bazel run //:verify -- -suite cpp -target darwin/amd64
```

The suite builds independent ordinary C++ executable controls with
`native_control.cpp`, then tests Bao archives. Supported cases run through both
purego registration and DWARF-inferred assembly bindings. Go consumers use
`CGO_ENABLED=0`, unavailable C/C++/Rust compiler paths, and offline module
resolution after setup. Each runs at `GOMAXPROCS=1` and `4`, then after ad-hoc
Hardened Runtime signing and strict signature verification. Negative controls
omit constructor invocation, TLS finalization, or static finalization and must
fail the corresponding state checks. Existing output is not reused as proof
for changed native inputs.

The suite returns `CHECKED_WITH_LIMITATIONS`, with separate `PASS`, native
control failures, and `UNSUPPORTED` entries. A successful suite exit means the
supported checks and expected rejections behaved as recorded; it does not mean
C++ stack unwinding works through Bao. The tested profile is Apple Clang 21,
SDK 26.5, and Go 1.26.10. Local amd64 execution on an Arm Mac uses Rosetta;
native Intel CI runs are separate. The separate
[Linux C++ suite](../cpp_linux/README.md) covers GCC and Clang with libstdc++ on
arm64/amd64 and QEMU loong64/ppc64le, including working C++ exception handling
through ELF unwind tables. The cross C++ release legs require the Rust examples
to pass in the same image.

## Producing the TLS example

From this directory, build an archive with its private handle:

```sh
clang++ -std=c++20 -target arm64-apple-macos11 -O2 -g \
  -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -c tls.cpp -o tls.o
clang++ -std=c++20 -target arm64-apple-macos11 -O2 -g \
  -c dso_handle.cpp -o dso_handle.o
ar rcs libcpp-tls.a tls.o dso_handle.o
bao build -target darwin/arm64 -bindings dwarf \
  -symbol bao_example_run -symbol bao_example_check_finalized \
  -o native libcpp-tls.a
```

Ship the generated Go/assembly/`.syso` files with their notices. In a consumer
module, import that package and keep execution/finalization on one OS thread:

```go
runtime.LockOSThread()
defer runtime.UnlockOSThread()
if native.BaoExampleRun() != 42 {
    panic("C++ TLS test")
}
native.TLSFinalizeCurrentThread()
if native.BaoExampleCheckFinalized() != 42 ||
    native.TLSLiveBlocks() != 0 || native.TLSDestroyedBlocks() != 9 {
    panic("C++ TLS teardown")
}
```

The workers have joined before `BaoExampleRun` returns. Finalization must happen
after the last native use of TLS. A bare `go build`/Go process exit does not
replace this cleanup. Typed consumers need no purego module; omit `-bindings`
to select runtime registration instead.

For static destruction, build `static_lifetime.cpp` with the same handle and
select `bao_example_run`, `bao_example_finalize`, and `bao_example_static_state`.
After `BaoExampleRun()` returns 42, call `BaoExampleFinalize()` explicitly when
no threads can still use those objects. It returns 42, and
`BaoExampleStaticState()` becomes 43 (all three destructors ran in order 3/2/1).
Repeated finalization does not run destructors again. This fixture has no TLS
objects; when combining both lifetimes, stop workers and finalize their TLS
before destroying static resources that TLS destructors may need.

Exceptions must never cross Go frames. The exception fixture catches inside
C++, but the tested compact personality/LSDA representation is still rejected
by Bao. Retaining source-level DWARF for signature inference does not itself
provide support for native exception metadata. No embedded runtime helpers or
translator unwind rules were weakened for these examples.
