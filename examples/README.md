# Independent Rust libraries

These libraries exercise Bao without gpui-go or any third-party Rust crates.
Each directory is a complete Cargo `staticlib` package with explicit bindings to
public macOS APIs. All keep Rust's unwind panic strategy. They export
`bao_example_run() -> uint64_t`: 42 means the native checks passed; other values
identify a failed check in the source.

| Library | Native behavior checked |
| --- | --- |
| [core_foundation](core_foundation/src/lib.rs) | Unicode CFString serialized as a binary property list and decoded; CF object ownership |
| [core_graphics](core_graphics/src/lib.rs) | Draw an RGBA bitmap and compare every pixel; floating-point arguments and CGRect by value |
| [core_text](core_text/src/lib.rs) | Resolve Helvetica glyphs and compare individual and total advances |
| [security](security/src/lib.rs) | Fill two buffers using SecRandomCopyBytes and the exported kSecRandomDefault data symbol |
| [image_io](image_io/src/lib.rs) | Encode a bitmap to PNG in memory, decode it, render it and compare pixels |
| [foundation](foundation/src/lib.rs) | NSString creation, uppercase conversion, UTF-8 extraction and autorelease pool through typed Objective-C messages |
| [accelerate](accelerate/src/lib.rs) | Strided vDSP vector addition and dot product checked against scalar Rust |
| [rust_runtime](rust_runtime/src/lib.rs) | CoreFoundation call; two native initializers with argc/argv/environ; data import fixup; pointer addend; 128-byte storage/TLS alignment; eight std threads; nine TLS destructors; caught panic with two RAII drops |

The separate [Linux arm64 runtime library](linux_runtime/README.md) exercises
the native ELF path with Rust std, glibc callbacks, constructors, unwinding and
thread/TLS teardown. It has its own Cargo workspace and verification suite.

The [C++ lifecycle probes](cpp/README.md) trace the runtime example's exception,
TLS, static-initializer and destructor behavior. They include supported cases
and explicit unsupported boundaries; a Rust runtime pass is not used as proof
of C++ compatibility.

The [Linux C++ runtime library](cpp_linux/README.md) exercises GCC and Clang
with libstdc++ on arm64, amd64, loong64 and ppc64le, including exception/RAII unwinding, aligned
TLS/destructors, static construction and explicit finalization. Its Docker
suite checks both binding modes and the scalar calling convention. Cross
CI/release checks require the Rust runtime and typed-binding examples to pass
first; loong64/ppc64le execution uses QEMU.

The Foundation example sends messages to existing system classes. It does not
define native Objective-C classes or require ObjC/Swift image registration.
The Security example is a randomness API smoke test, not an entropy assessment.
These examples need no window, GPU, network, keychain access, permissions dialog,
or files outside their build directory.

On macOS/arm64, run the complete maintainer verification from the Bao root:

```sh
bazel run //:verify -- -suite darwin
```

The Go verifier compiles archives through `bao build`,
combines their members using Apple's `ld -r`, translates each into a fresh Go
package, builds and runs the shared [Go consumer](consumer/main.go.tmpl), checks
final section alignment, signs with ad-hoc Hardened Runtime, strictly verifies
the signature, and executes again. Consumer builds have `CGO_ENABLED=0` and
deliberately invalid `CC`, `CXX` and `RUSTC`. Setup fetches purego v0.11.3 with
`go get`; consumer builds then disable module networking. The runtime case also checks that removing FDE
registration still links but fails to catch the native panic.

Build and translate one library manually:

```sh
bazel run //:bao -- build -manifest-path examples/core_graphics/Cargo.toml \
  -offline -locked -symbol bao_example_run -o native
```

This command selects runtime registration. Its generated package uses purego to
initialize native runtime metadata. Import it from a Go application that calls
`purego.RegisterFunc` on `SymbolAddr0()`;
the shared consumer is a complete example. Run
`go get github.com/ebitengine/purego@v0.11.3` in its Go module, then build with
`CGO_ENABLED=0 go build`. Only the library producer needs Rust, the SDK and native
linker. Shipping the generated Go/assembly/`.syso` files makes those tools
unnecessary for consumers.

To generate typed functions without a purego module dependency, infer the same
export's C ABI signature during the producer build:

```sh
bazel run //:bao -- build -manifest-path examples/core_graphics/Cargo.toml \
  -offline -locked -bindings dwarf -symbol bao_example_run -o native-typed
```

Bao requests full release DWARF from Cargo and emits `BaoExampleRun()` plus
assembly adapters and bundled runtime support. Import this generated package
and call `native.BaoExampleRun()` directly; build with `CGO_ENABLED=0 go build`
without importing or fetching purego. The shared consumer template above is
for runtime registration; its `RegisterFunc` call is replaced by the direct
typed call for this mode. Runtime teardown and TLS finalization still apply.

See the [consumer usage](../README.md#using-generated-go-packages) and
[developer binding modes](../README.md#choosing-a-binding-mode) for the differences
in API, type declarations, module packaging and runtime compatibility. Keep the
bundled bootstrap notices for typed bindings, and the original Rust standard
library licenses and notices in either mode, alongside Bao's Apache-2.0 license.
