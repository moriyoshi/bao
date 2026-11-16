# Bao

[![Actions CI](https://github.com/moriyoshi/bao/actions/workflows/ci.yml/badge.svg)](https://github.com/moriyoshi/bao/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/moriyoshi/bao.svg)](https://pkg.go.dev/github.com/moriyoshi/bao)

![bao](assets/bao.jpg)

Bao translates native C/C++/Rust object code into `.syso` packages that stock Go can
link without cgo or a consumer C compiler. Its primary examples are small Rust static libraries
using macOS frameworks, with no third-party Rust crates; see [examples](examples/README.md).

The maintained Darwin path targets macOS/arm64 and macOS/amd64 with Go 1.26.11. It preserves Rust
unwinding, thread-local storage and destructors, native initializers, imported
system functions/data, and native section alignment. Library developers can generate
typed assembly bindings or expose addresses for PureGo runtime registration;
see [function bindings and DWARF inference](#function-bindings-and-native-debug-stripping). Library producers need Rust and Apple's SDK/linker. The translator
itself is pure Go, has no module dependencies, and embeds small native runtime
objects built from the included Apache-2.0 sources.

Translation happens at build time. Native code is linked into the executable;
there is no runtime extraction, application dylib loader, executable-memory
allocation, custom Go toolchain or consumer C/Rust compiler. System libraries
remain dynamically linked through the target OS loader. Separate Linux ELF
profiles cover arm64, amd64, loong64 and ppc64le; see
[platform support](#platform-support) and the [Linux reference](docs/linux.md).

- [Library consumers](#library-consumers): use a Bao-built library in a Go
  application and optionally verify its signed release.
- [Library developers](#library-developers): build native code, generate and
  distribute Go packages, and sign library releases.
- [Bao maintainers and developers](#bao-maintainers-and-developers): change
  Bao itself, run its verification suites, and maintain its runtime helpers.
- [FAQ](#faq): answers to common questions about dependencies, linking and support.

## Walkthrough example

This example follows the C `add` library pattern: the author compiles a native
archive, uses Bao to infer typed bindings, and supplies a Go module. A separate
application then imports the generated package. The commands below target
macOS arm64 and use stock Go 1.26.11. The author needs Bao, Clang, `ar`, and
Apple's SDK and linker; the consumer needs the generated module and compatible
system libraries. The example uses placeholder module paths and a local
replacement, so no repository or package download is required.

### Author: build and package the library

Start in a directory where you can create a new `bao-walkthrough` directory:

```sh
mkdir bao-walkthrough
mkdir bao-walkthrough/library bao-walkthrough/consumer
cd bao-walkthrough/library
cat > entrypoint.c <<'EOF'
int add(int a, int b) {
    return a + b;
}
EOF
cat > go.mod <<'EOF'
module example.com/bao-test/lib

go 1.26.0
EOF
```

Compile with full DWARF so Bao can infer the C ABI signature, then make the
archive and generate the package. `-min-os 26.0` sets the minimum macOS
version for this example; choose a suitable deployment target for your own
library and SDK.

```sh
clang -gdwarf -O3 -c -o entrypoint.o entrypoint.c
ar -q libtest.a entrypoint.o
bao build -target darwin/arm64 -o ./native -bindings dwarf \
  -symbol add -package native -min-os 26.0 libtest.a
```

Bao creates `native/`, which must not already exist. The inferred
`native/bao-signatures.json` describes `Add(int32, int32) int32`. Ship the module's
`go.mod` and the complete generated `native/` directory, including its Go,
assembly, `.syso`, metadata and license/notice files. The source and archive
are producer inputs, not needed by the consumer. For a real release, use your
own module path and publish the complete module; see
[distributing a generated package](#distributing-a-generated-package) and
[signing library releases](#signing-library-releases).

### Consumer: import and call the package

For this local demonstration, the consumer uses a `replace` directive to refer
to the author's module. From the `library` directory above:

```sh
cd ../consumer
cat > go.mod <<'EOF'
module example.com/bao-test/app

go 1.26.0

require example.com/bao-test/lib v0.0.0

replace example.com/bao-test/lib => ../library
EOF
cat > main.go <<'EOF'
package main

import (
    "fmt"

    "example.com/bao-test/lib/native"
)

func main() {
    fmt.Println(native.Add(1, 2))
}
EOF
go build -o app .
./app
```

The program prints `3`. The build works with cgo enabled or disabled, so
`CGO_ENABLED` need not be set. Typed bindings need no PureGo module dependency,
and this function has no pointer or TLS cleanup for the caller to manage. For a
published module, replace the placeholder module path and local `replace` with
the library's real import path and version. If the application also has its own
cgo dependency, it needs Go's [internal linker](#using-generated-go-packages) and
a C compiler.

## Platform support

| Target | Profile | Native input | Runtime checks ran on | cgo-enabled consumer builds |
| --- | --- | --- | --- | --- |
| darwin/arm64 | Maintained | Objects, archives, Cargo staticlibs; [dylibs](docs/darwin.md#dylib-input) | Native macOS | Executed |
| darwin/amd64 | Maintained | Same | Rosetta 2 on macOS arm64 | Executed under Rosetta 2 |
| linux/arm64 | Maintained | Objects, archives, Cargo staticlibs; [shared objects](docs/linux.md#shared-objects) | Native Docker | Executed in native Docker |
| linux/amd64 | Maintained | Same | QEMU in Docker locally; a native runner in hosted CI | Bootstrap alone under emulation, not with a translated library |
| linux/loong64 | Experimental | Same | QEMU | Executed under QEMU |
| linux/ppc64le | Experimental | Same | QEMU | Executed under QEMU |
| windows/amd64 | [Producer profiles](docs/windows.md#producer-reference) | COFF objects, archives, Cargo staticlibs; [DLLs](docs/windows.md#dll-input) | Wine | Executed under Wine with LLVM-MinGW |
| windows/arm64 | Same | Same | Wine (arm64) | Cross-linked, not executed |

Consumers build with stock Go 1.26.11 on every target. The cgo column covers
both an application with no other cgo dependency and one whose own cgo
dependency needs the [internal linker](#using-generated-go-packages); other
toolchains need separate verification. Remaining gaps:

- Native Windows CI is configured, and it is a release gate, but its results
  are pending.
- Physical LoongArch and PowerPC hardware are unverified.
- The Linux amd64, loong64 and ppc64le C++ lifecycle suites last passed with
  Go 1.26.10.
- The hosted native macOS Intel check has not run with the current SDK.

[JOURNAL.md](JOURNAL.md) records each run with its toolchains, environment and
negative controls.

## Library consumers

You use a library generated with Bao in a Go application. The library developer
supplies the native package; your work is to call its API, build the application,
and optionally authenticate the library release.

### Using generated Go packages

A Bao-built library can provide generated typed bindings without a PureGo module
dependency, or use PureGo for runtime registration. The library developer chooses
the mode when generating the package. Use the API shipped by that library:

| | Generated typed bindings | Runtime registration with PureGo |
| --- | --- | --- |
| Calling code | Call an exported Go function such as `native.Add(19, 23)` | Register a Go function variable with `purego.RegisterFunc`, or call a wrapper provided by the library |
| Purego module dependency | None required by the generated package | Required, even if the library hides registration behind its own API |
| Function types | Declared by the library developer and emitted as typed Go functions | The registered Go function type must match the native C ABI |
| Application build | `go build`, with cgo enabled or disabled | `CGO_ENABLED=0 go build`, with PureGo available in the module graph |

Both modes link native code into the executable. Consumers need the supplied Go,
assembly and `.syso` files, stock Go 1.26.11, and compatible target system libraries;
they need neither Rust nor a native compiler/SDK. Ordinary application builds do
not invoke Bao. Changing a generated package's binding mode requires regeneration
by the library developer; it is not an application `go build` option.

Typed packages build with Go's defaults whether cgo is enabled or not; an
application with no other cgo dependency needs no `CGO_ENABLED` setting, linker
flag or C compiler. On Darwin and Linux the bundled bootstrap detects whether
`runtime/cgo` is linked when the program starts and defers to it if so; Windows
packages need no bootstrap. [Platform support](#platform-support) lists where
cgo-enabled builds have run.

If the application also has its own cgo dependency, which links `runtime/cgo`,
it must use Go's internal linker:

```sh
CGO_ENABLED=1 go build -ldflags=-linkmode=internal
```

The application needs a working C compiler for its cgo dependencies. Go's
default external linking fails on supported examples with Bao-generated objects;
dependencies requiring external linking remain unsupported in this profile. On
Linux, the standard `net` and `os/user` packages link `runtime/cgo` when cgo is
enabled, so applications using them, including through `net/http`, need either
this flag or `CGO_ENABLED=0`.

Packages generated by earlier Bao versions import `runtime/cgo` when cgo is
enabled and so still need `CGO_ENABLED=0` or the internal linker flag;
regenerate them with the updated Bao. The PureGo mode retains its documented
cgo-disabled profile.

#### Calling generated typed bindings

Import the supplied library package and call its exported functions directly.
For the `Add` declaration in the [developer manifest example](#explicit-declarations):

```go
fmt.Println(native.Add(19, 23)) // 42
```

No `purego` import, `purego.RegisterFunc` call, or `go get` for PureGo is needed
for this package. The generated functions and assembly perform the foreign-call
transition using the runtime support bundled with the library. Build normally:

```sh
go build
```

#### Calling through PureGo

If the library exposes addresses, import `github.com/ebitengine/purego` and
register a function variable with the correct signature before calling it.
For a selected `native_add(uint64_t, uint64_t) -> uint64_t` export:

```go
var add func(uint64, uint64) uint64
purego.RegisterFunc(&add, native.SymbolAddr0())
fmt.Println(add(19, 23)) // 42
```

`SymbolAddr0()` returns an address, not a callable Go function. The PureGo
registration provides the foreign-call transition. Do not cast a native address
to a Go function or call it as Go assembly. A complete runtime-registration
consumer is in [examples/consumer/main.go.tmpl](examples/consumer/main.go.tmpl).

This mode also uses PureGo inside the generated package to initialize native
runtime metadata. A library may perform registration internally and expose an
ordinary Go wrapper, so application code need not always import PureGo directly;
the module dependency still remains. In the application's Go module, ensure the
published dependency is available (verified at v0.11.3):

```sh
go get github.com/ebitengine/purego@v0.11.3
CGO_ENABLED=0 go build
```

#### Building for the target

For either binding mode, select the library's target when cross-building. For
Linux arm64:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build
```

See [platform support](#platform-support) and the
[platform reference](#platform-reference) for platform limitations.

### Runtime caveats

#### Compatibility and pointer lifetimes

Generated typed bindings bundle a bootstrap that installs process-wide runtime
hooks when `runtime/cgo` is not linked. Use **one bundled bootstrap per
executable**; combining it with another bundled bootstrap or PureGo's bootstrap
is unsupported, and two bundled bootstraps fail at link time. On Darwin and Linux, when an application
links `runtime/cgo` through a cgo dependency, the bootstrap defers to it at
startup and the application uses internal linking. Native callbacks into Go are not
supplied by this scalar generator. Other runtime combinations require separate
verification.

For example, this import combination is unsupported, including when the imports
are introduced by dependencies:

```go
import (
	_ "example.org/native"           // Generated typed package with a bundled bootstrap.
	_ "github.com/ebitengine/purego" // Adds a second bootstrap provider.
)
```

Use the typed package on its own, or have the library developer provide its
runtime-registration variant for an application already using PureGo. A second
generated package bundling its own bootstrap has the same compatibility issue.

Native code must obey Go's foreign-pointer lifetime rules in either mode.
Generated typed wrappers pin objects passed as `pointer` arguments and keep
them alive for the synchronous call; integer `uintptr` arguments receive no
such pinning. This does not grant native code permission to retain Go pointers
or Go pointers to memory containing other Go pointers. Follow the library's
ownership and lifetime contract when using PureGo registration as well. Return
pointers remain subject to the native library's ownership and cleanup rules.

For the [manifest's `Process` function](#explicit-declarations), suppose the
native implementation reads or writes the supplied bytes only during the call
and retains no pointer. Inside a Go function, with `unsafe` imported:

```go
buf := []byte("bao") // A nonempty backing array containing no Go pointers.
status := native.Process(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
fmt.Println(status) // The typed wrapper pins the buffer until Process returns.
```

Pass the address as `unsafe.Pointer`, matching the manifest's `pointer` type.
A parameter declared as `uintptr` is treated as an integer and receives no
automatic pointer pinning. The native function must not retain the buffer
address after the call returns.

For a runtime-registration variant selecting `native_process` as its first
export, explicit pinning can cover the same synchronous call. With `purego`,
`runtime` and `unsafe` imported, inside a Go function:

```go
var process func(unsafe.Pointer, uintptr) int32
purego.RegisterFunc(&process, native.SymbolAddr0())

buf := []byte("bao")
var pin runtime.Pinner
pin.Pin(&buf[0])
defer pin.Unpin()
status := process(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
runtime.KeepAlive(buf)
fmt.Println(status)
```

This example does not permit native code to retain the pointer after the call.
If a returned pointer transfers ownership of a native allocation, use the
library's documented release function; Go's garbage collector does not supply
that native cleanup.

#### TLS finalization

The startup thread needs explicit TLS finalization after native teardown because
Go process exit does not run native pthread destructors on that thread. Call
`native.TLSFinalizeCurrentThread()` on the locked calling OS thread only after
stopping native activity and releasing its TLS references. Native pthread exits
finalize automatically. The generated counters report blocks owned by that image;
finalizing one thread does not synchronize with others.

For a typed package generated from the [Rust runtime example](examples/rust_runtime/src/lib.rs),
replace the illustrative import path below with that package's actual path:

```go
package main

import (
	"fmt"
	"runtime"

	native "example.org/native"
)

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		native.TLSFinalizeCurrentThread()                           // Runs before UnlockOSThread.
		fmt.Printf("live TLS blocks: %d\n", native.TLSLiveBlocks()) // 0 here.
	}()

	if got := native.BaoExampleRun(); got != 42 {
		panic(fmt.Sprintf("native check returned %d", got))
	}
	// BaoExampleRun has joined its native workers before returning.
}
```

For the runtime-registration variant, keep the same locking and deferred cleanup,
import PureGo, and replace the typed call with a registered function:

```go
var run func() uint64
purego.RegisterFunc(&run, native.SymbolAddr0())
if got := run(); got != 42 {
	panic(fmt.Sprintf("native check returned %d", got))
}
```

An application managing longer-lived native work must stop and join that work
and release references to the calling thread's TLS before finalization. Do not
move finalization into another goroutine: locking that goroutine would not
select the original OS thread. `os.Exit` and `log.Fatal` skip the deferred
cleanup shown above.

#### Linux runtime finalization

Generated Linux packages expose `FinalizeRuntime()` to run retained ELF fini
arrays once, in reverse entry and priority order. Stop and join native workers,
then complete caller TLS cleanup and explicit C++ shutdown in the library's
required order before calling it. Caller TLS cleanup must run on its locked OS
thread. This function does not replace C++ shutdown,
run automatically at Go process exit, or permit subsequent native use or image
unloading. `FinalizeRuntime` is a reserved binding name. Use one combined native
runtime image per executable; exceptions must remain within native frames.

### Windows amd64 / arm64

Use the supplied Go package with stock Go 1.26.11 and either generated typed
bindings or PureGo registration. C/C++ and GNU Rust std libraries are supported
within the [documented producer profiles](docs/windows.md#producer-reference).
Applications need no Rust/C++ compiler, SDK or native linker.

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build
```

Use `GOARCH=arm64` with a package generated for ARM64. Install the matching
runtime DLLs specified by the library publisher. Packages with bundled language
runtimes still use Windows system DLLs.

Keep TLS-dependent calls on the same locked OS thread. Stop and join native
workers before calling `native.Shutdown()`; it finalizes caller TLS and static
objects and is safe to call again. Go process exit does not call it. If releasing
a calling OS thread earlier, call `native.TLSFinalizeCurrentThread()` before
unlocking it. Keep image-owned FLS keys inside the library, and do not resume
native work after shutdown.

Exceptions and Rust panics must be caught within native code. MSVC Rust std,
Windows/386 and ARM64EC are unsupported. See
[platform support](#platform-support) for where this has run and the
[Windows reference](docs/windows.md#implementation-notes) for implementation
notes.

### Consumer-controlled signature verification

`bao verified-build` is an explicitly invoked build entry point for consumers
who obtain **Bao, stock Go 1.26.11, their policy and public keys independently
of the account publishing a native module**. This is an initial restrictive
profile, not a deployed signing service or a claim that signed code is benign.
Normal `go build`, imports and `go get` do not automatically invoke it.

| Command | Purpose |
| --- | --- |
| `version` | Report Bao's build version and verified consumer linker |
| `verify` | Scan the current module's downloaded dependencies without building or running code |
| `verified-build` | Authenticate approved complete native modules and build with private snapshots/cache |

`version` and `verify` support `-json`.

A consumer pins each approved release's key and exact payload digest in a
policy obtained independently of the publisher. `bao verify` then scans the
module's downloaded dependencies, and `bao verified-build` builds an executable
from authenticated private snapshots with a fresh build cache, through stock Go
or a bounded rules_go (Bazel) backend. See
[signature verification](docs/signature-verification.md) for the policy format,
both build flows and the trust limits.

## Library developers

You compile the native library and use Bao to produce and distribute its Go
package. Choose the exported API and target, then generate bindings and
optionally sign the complete module for consumers.

### CLI releases

Download CLI archives from [GitHub Releases](https://github.com/moriyoshi/bao/releases)
for macOS arm64/amd64 or Linux amd64/arm64/loong64/ppc64le. CLI host availability
is separate from native translation support; each native profile has its own
checked compiler/runtime scope. macOS binaries have no Developer ID signature
or Apple notarization.

Download the archive, `SHA256SUMS`, and `provenance.sigstore.json`. For example,
using a macOS arm64 release (replace `v0.1.0` with the downloaded version):

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
gh attestation verify bao_v0.1.0_darwin_arm64.tar.gz --repo moriyoshi/bao \
  --signer-workflow moriyoshi/bao/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 \
  --bundle provenance.sigstore.json
tar -xzf bao_v0.1.0_darwin_arm64.tar.gz
./bao_v0.1.0_darwin_arm64/bao version -json
```

Each archive includes the CLI, version/commit metadata, and license/provenance
texts. Checksums detect corruption; GitHub provenance authenticates the workflow
origin and depends on trust in the repository, GitHub and its runners. It does
not replace consumer-pinned approvals for Bao's
[signature verification facility](#consumer-controlled-signature-verification).

### Toolchain CLI

Examples below use `bao`; put the extracted executable on `PATH` or use its
full path. Check the producer toolchain and available targets:

```sh
bao doctor
bao targets
bao help build
```

| Command | Purpose |
| --- | --- |
| `build` | Compile a Cargo staticlib or combine a static archive, then generate a Go package |
| `translate` | Translate an already-combined object; auto-detect Darwin/ELF input |
| `inspect` | Report Darwin raw-input compatibility or Linux ELF/Windows COFF structure |
| `bindings` | Infer selected C ABI function types from full native DWARF |
| `objcopy` | Rename, wrap, prefix, localize or strip symbols in an ELF, Mach-O or COFF object or archive; see [symbol edits](#symbol-edits) |
| `doctor` | Check the full producer toolchain; installs nothing |
| `targets` | List target names and Rust triples |
| `sign`, `keygen` | Produce Ed25519 release envelopes and local signing keys |

The opt-in [signature verification facility](#consumer-controlled-signature-verification) requires independently
trusted Bao, Go, policy and public keys. It authenticates complete generated
modules and actual linker archive payloads. It does not establish a publisher's
trustworthiness or install an automatic import-time verification hook.

`build`, `translate`, `doctor` and `targets` support `-json`.
Help succeeds with exit 0; usage errors use 2, build failures use 1, and canceled
producer commands use 130. Options precede positional inputs. Existing output
directories are refused. Producer builds stage a complete package before
publishing it and remove their own temporary files on failure.

### Building from Go

A producer that generates its native package from Go code, such as a
`go generate` step, can import bao as a module instead of running a
separately installed `bao`. The bao version then comes pinned through
`go.mod` and `go.sum`. Package `github.com/moriyoshi/bao/build` runs
`bao build` with the same behavior; its `Options` fields mirror the
command's flags.

```go
err := build.Run(ctx, build.Options{
	Input:   "glue.o",
	Output:  "native",
	Target:  "linux/arm64",
	Sysroot: "/srv/sysroot",
	Symbols: []string{"glue_run"},
	Wrap:    []string{"pthread_create", "pthread_join"},
	Linux: build.LinuxOptions{
		SharedObject:      "libpython3.13.so.1.0",
		MaxSymbolVersions: []string{"GLIBC_2.18"},
	},
	Stderr: os.Stderr,
})
```

- `Args` takes any other `bao build` flags, as on the command line, such as
  the per-input symbol edits.
- `Options.CommandLine` shows the arguments `Run` passes.
- `Run` can run more than once in one process, for example once per target.
- Combining archives still runs the native partial linker as the command
  does. A single relocatable object, with or without `Linux.SharedObject`,
  needs none.
- An unstamped build records bao's module version from the importing
  program's build information in `bao-build.json`.

### Producing a Go package

Native producer builds need the host Rust/Cargo toolchain and a compatible
native linker/SDK or Linux sysroot. Consumers of the generated package need
neither Rust nor a native compiler.

Build directly from a Cargo member manifest, a workspace manifest with
`-cargo-package NAME`, a crate directory, a static archive or a combined object.
Without a positional input, `build` uses `./Cargo.toml`. Cargo builds select one
`staticlib`, use the release profile, and follow Cargo's reported artifact path,
including configured target directories. `-offline` and `-locked` are forwarded
to Cargo. An ambiguous workspace requires `-cargo-package`.

The following examples omit `-bindings` and produce the PureGo runtime mode.
To produce a package without a PureGo module dependency, use
`-bindings signatures.json` or `-bindings dwarf` as described under
[choosing a binding mode](#choosing-a-binding-mode).

```sh
bao build -manifest-path examples/core_graphics/Cargo.toml \
  -offline -locked -symbol bao_example_run -o ./native

# Or start from a library produced elsewhere.
bao build -target darwin/arm64 \
  -symbol native_fn -o ./native /path/to/libnative.a
```

The output directory must be new and its parent must exist. Generated files
include Go declarations/runtime initialization, assembly address accessors,
`.syso` objects and `bao-manifest.json` with input/output hashes and the actual
translation plan. `bao-build.json` additionally records producer commands and
source/combined hashes. Repeated `-symbol` flags select public C ABI entrypoints, named
without Mach-O's additional leading underscore. Accessors `SymbolAddr0`,
`SymbolAddr1`, etc. follow flag order. See [using generated Go packages](#using-generated-go-packages)
for consumer calls and build commands.

Darwin/Linux archives are partially linked using the producer's native `ld`.
Windows COFF member selection happens inside Bao; see the
[Windows producer reference](docs/windows.md#producer-reference). macOS SDK discovery uses `xcrun`, or pass
`-sdk`. Linux defaults to `/` only when the producer matches the target; cross translation needs
`-sysroot`. `-ld` selects a compatible cross linker. Combining Darwin archives
on another host requires a compatible Apple partial linker; precombined-object
translation itself needs no native compiler/linker.

### Symbol edits

`bao build` can rename, wrap, prefix, localize, weaken or strip symbols, remove
sections and add symbols in its ELF, Mach-O and COFF inputs before combining
them, so a producer needs neither `objcopy` nor a second relinking step.
`bao objcopy` applies the same edits to one object or archive, including ELF32,
big-endian ELF, 32-bit and universal Mach-O, and COFF bigobj files. The flags
follow ld.lld and llvm-objcopy: `-wrap`, `-redefine-sym(s)`, `-prefix-symbols`,
`-localize-symbol(s)`, `-localize-hidden`, `-keep-global-symbol(s)`,
`-globalize-symbol`, `-weaken-symbol`, `-strip-symbol`, `-strip-unneeded`,
`-remove-section`, `-only-section`, `-add-symbol` and `-wildcard`. See
[symbol edits](docs/symbol-edits.md) for their semantics, the rules for each
format and examples.

### Function bindings and native debug stripping

Choose the calling API and dependency profile before distributing your package.
Consumers use the supplied API as described in
[using generated Go packages](#using-generated-go-packages).

#### Choosing a binding mode

| | Generated typed bindings | Runtime registration with PureGo |
| --- | --- | --- |
| Producer options | `-bindings signatures.json`, or `-bindings dwarf -symbol NAME` | Omit `-bindings`; select exports with `-symbol NAME` |
| Type information | An explicit scalar C ABI manifest, or full type DWARF for inference | Matching Go function declarations supplied at registration; no type DWARF required |
| Generated call support | Typed Go functions, fixed-signature assembly adapters and bundled runtime bootstrap | Address accessors and initialization code using the PureGo module |
| Module packaging | No PureGo module requirement; ship all generated runtime sources, headers and notices | Declare the PureGo dependency in the published module |

For example, expose a C ABI `native_add` function for runtime registration with:

```sh
bao build -target darwin/arm64 -symbol native_add -o native libnative.a
```

The consumer registers `SymbolAddr0()` with PureGo, or you can provide a Go
wrapper that does so inside your library. Wrapping registration does not remove
the PureGo dependency: generated initialization uses it too.

To expose the same function as `native.Add` without a PureGo module requirement,
provide the manifest below and pass `-bindings signatures.json`. Bao replaces
the generated package's PureGo-based initialization calls as well as generating
the public call adapters. Keep these generated files together; deleting PureGo
imports from a runtime-mode package is not a conversion to typed bindings.

Typed generation supports the scalar signatures listed below. If your interface
uses unsupported types, provide scalar C/Rust wrappers or choose runtime
registration within PureGo's own supported ABI profile. Both modes require
correct C ABI declarations and use a Go/native runtime transition. They retain
the same native translation, system-library and TLS requirements.

Generated mode bundles adapted PureGo v0.11.3 `internal/fakecgo` bootstrap sources
with Apache/BSD notices and provenance. It removes the PureGo **module dependency**;
it still includes those adapted sources. Plan for the
[one-bootstrap-per-executable constraint](#compatibility-and-pointer-lifetimes)
when choosing a mode, including whether the application already uses PureGo.

#### Explicit declarations

Provide a JSON manifest describing C ABI exports:

```json
{
  "schema": 1,
  "abi": "c",
  "functions": [
    {"name": "Add", "symbol": "native_add", "params": ["uint64", "uint64"], "result": "uint64"},
    {"name": "Process", "symbol": "native_process", "params": ["pointer", "uintptr"], "result": "int32"}
  ]
}
```

```sh
bao build -bindings signatures.json -o native libnative.a
```

The manifest supplies the native exports; additional `-symbol` options retain
the address API for those symbols. Generated functions can be called directly,
for example `native.Add(19, 23)`. `pointer` maps to `unsafe.Pointer`; other type
names map to the corresponding Go scalar types. An omitted or `void` result
means no return value. The initial profile supports signed/unsigned 8/16/32/64
bit integers, `uintptr`, opaque pointers, `float32` and `float64`, with up to
32 scalar arguments. It handles each target's argument registers and stack
rules, including Darwin arm64 narrow packing, LoongArch float-to-integer
register fallback and PowerPC ELFv2 parameter positions.

Aggregates, arrays by value, variadic calls, vectors, `bool`, long double,
128-bit integers and automatic Go callbacks are rejected. Go strings/slices
are not implicit conversions; pass explicit pointer/length pairs. For wider
interfaces, provide a scalar C/Rust wrapper or use the PureGo address mode within
its own supported type profile. Declarations must match the real C ABI. A
manifest does not make an incorrectly declared foreign function safe.

Document your library's pointer ownership and cleanup rules for callers.
Generated wrappers follow the [consumer pointer rules](#compatibility-and-pointer-lifetimes).

#### Inference from optimized code with full DWARF

Full debug DWARF can describe parameter and return types even when machine code
is optimized. Select the C ABI exports and ask Bao to infer the manifest:

```sh
clang -O2 -g -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
  -c library.c -o library.o
bao bindings -symbol native_add -symbol native_process \
  -o signatures.json library.o
bao build -bindings signatures.json -o native library.o
```

Or infer and generate in one producer invocation:

```sh
bao build -bindings dwarf -symbol native_add -o native libnative.a
bao build -bindings dwarf -symbol bao_example_run \
  -manifest-path examples/rust_runtime/Cargo.toml -o native
```

Cargo inference stays in the optimized release profile and requests full
`profile.release.debug=2` with `profile.release.strip="none"` through command
options. Bao does not edit the Cargo manifest or global compiler configuration.
For an already compiled archive/object, the producer must retain full debug
information (`rustc -O -C debuginfo=2`, or `clang/gcc -O2 -g`). Line tables
alone and unwind metadata alone do not provide complete function types.

Inference reads the **original input**, including individual ordinary archive
members, before partial linking and stripping can discard type information. It
follows typedefs, qualifiers, specification and abstract-origin references;
optimized-out parameter locations do not by themselves erase their types.
The selected function must have an external object definition and an
unambiguous, supported source-level signature. Unsupported or conflicting
types, missing debug information and non-normal calling conventions fail
closed. It does not silently fall back to guessing types or runtime PureGo.

Selecting `-symbol` asserts that the export uses the C ABI. In particular,
DWARF does not reliably prove that a Rust function was declared `extern "C"`.
Export Rust functions accordingly. C++ entry points should use `extern "C"`
wrappers. External dSYM/DWO/debug companion files and source files are not
opened automatically. Bao accepts relocatable objects/archives for this flow,
not final executables or arbitrary shared libraries.

The generated package contains a reviewable `bao-signatures.json` plus
`bao-bindings.json`. These are **function type declarations**, distinct from
the cryptographic release envelopes used by [verified-build](#consumer-controlled-signature-verification).
Inference does not establish authenticity, provenance or code safety.

#### Stripping

`build` and `translate` default to `-strip-debug=true`. Bao removes native debug
sections, their relocation sections and debug-only/file symbols, rebuilding
section/symbol indices. Mach-O DWARF/STABS and ELF `.debug*`, `.zdebug*` and
related debug metadata are removed. The source object/archive is untouched.
`bao-debug.json` records the original/stripped hashes and removed section count.

Stripping happens **after inference**. Native EH frames, compact-unwind data,
LSDA/exception tables, TLS, constructors, code and runtime data are retained.
Rust panic unwinding and destructor cleanup remain tested after stripping.
Removing debug information does not redact ordinary runtime strings or replace
licensing notices. Go's own final-executable debug information remains governed
by Go build flags. `-strip-debug=false` is available for diagnostics; retaining
arbitrary native debug relocations is outside the checked translation profile.
The low-level byte-preserving `pack` command retains its separate narrow profile.

`build` and `translate` also default to `-strip-bitcode=true`, independently of
`-strip-debug`. Bao drops embedded LLVM bitcode, which Go's linker never loads:
the whole Mach-O `__LLVM` segment (`__bitcode`, `__cmdline`, `__asm`) and ELF
`.llvmbc`/`.llvmcmd`, with their relocations and the symbols defined in them.
Rust's precompiled std and every crate built with `lto = "fat"` carry it, and
without this it was copied into the generated `.syso` as an unallocated section.
A retained code or data relocation into these sections fails translation instead
of leaving a dangling reference. The build log reports the dropped bytes, and
`bao-debug.json` records `removed_bitcode_sections` and `removed_bitcode_bytes`.
`-strip-bitcode=false` (`strip_bitcode` in the config file) keeps it. Windows
COFF always drops `.llvmbc`/`.llvmcmd` and other `IMAGE_SCN_LNK_REMOVE` sections,
so `-strip-bitcode=false` is rejected for Windows targets.

### Bundling language runtimes

A package can link a language runtime statically, within the checked profiles
below. OS libraries remain dynamic throughout.

| Target | Statically linked language runtime | Local execution |
| --- | --- | --- |
| macOS arm64 | Rust std/unwinder; LLVM libc++ without C++ exceptions | Native |
| macOS amd64 | Same bounded profile | Rosetta 2 |
| Linux arm64 | Rust std/unwinder; GCC libstdc++/unwinder | Native Docker |
| Linux amd64 / loong64 / ppc64le | Same glibc profile | QEMU in Docker |
| Windows amd64 / arm64 | LLVM-MinGW libc++/ABI/unwinder; GNU Rust std/unwinder | Wine; native Windows CI configured, pending |

Use repeated `bao build -link-archive PATH` arguments to search native runtime
archives. The producer snapshots every archive before linking and records its
SHA-256 in `bao-build.json`. Repeated `-link-notice PATH` arguments copy matching
license notices byte-for-byte into `bao-linked-license-N.txt` and record their
hashes. Supply the required notices for every bundled runtime; Bao does not
automatically determine license obligations or authenticate those files.
`-require-static-runtime` rejects recognized shared language-runtime imports
before publishing the package. It also scans generated bootstrap imports, but
does not audit arbitrary `dlopen`/`LoadLibrary`, renamed libraries or transitive
OS dependencies. Keep one compatible native runtime image per executable.

#### macOS runtimes

On macOS, `ci/darwin-static-runtime.sh arm64` (or `amd64`) builds the pinned LLVM
23.1.5 runtime profile and preserves its notices. It requires Git, CMake, Make
and the macOS SDK on the producer. Link `lib/libc++.a` for C++, or
`lib/libunwind.a` alongside a Rust staticlib, from the resulting
`.work/static-runtimes/darwin-ARCH` prefix. C++ exceptions remain unsupported;
Rust catch/unwind, aligned TLS, allocation, explicit C++ finalization and signed
execution are checked. Typed consumers without another cgo dependency need no
native compiler.

#### Linux runtimes

Linux packages can bundle C++ and Rust runtimes within the checked glibc
profile on arm64, amd64, loong64 and ppc64le. `bao build` can search extra
static archives for the native library's unresolved references. For example, on
a matching Linux arm64 GNU producer:

```sh
bao build -target linux/arm64 -sysroot / -bindings dwarf \
  -symbol bao_example_run -require-static-runtime \
  -link-archive "$(g++ -print-file-name=libstdc++.a)" \
  -link-archive "$(g++ -print-file-name=libgcc_eh.a)" \
  -link-archive "$(g++ -print-file-name=libgcc.a)" \
  -link-notice /path/to/runtime-copyright \
  -link-notice /path/to/runtime-license \
  -o ./native ./library.a
```

The input needs C ABI exports and DWARF for this binding mode. Use the target
cross compiler's archive paths and sysroot when cross-producing. Rust staticlibs
already contain Rust std; the checked Rust profile adds `libgcc_eh.a` and
`libgcc.a`. The producer retains the primary ELF input and searches dependency
archives as a group. It records input digests and copies explicitly supplied
license/notice bytes. Supply every required notice for the distributed native
code; packaging does not change its licenses.

With `-require-static-runtime`, the checked final executables retain
dynamic OS dependencies (`libc`, pthreads and dynamic lookup); this flag
does not make a fully static executable or authenticate third-party inputs.

Consumers finalize such packages with
[`FinalizeRuntime`](#linux-runtime-finalization).

#### Windows runtimes

On Windows, supply the matching LLVM-MinGW target prefix's `libc++.a`,
`libc++abi.a`, `libunwind.a`, `libmingwex.a`, compiler builtins archive and
`libucrt.a` compatibility wrappers, with their LLVM and MinGW notices. Pass
`-windows-cxx-runtime libc++ -require-static-runtime`. Bao selects ordinary
native objects from explicitly EC-indexed hybrid archives; ARM64EC code remains
unsupported. Import-library declarations do not become native definitions or
implicitly grant new DLL mappings. The checked suite exercises C++ throw/catch,
TLS destructors, constructors/finalizers and multi-file COMDAT selection.
MSVC `/MT` is still unsupported because its guard metadata needs additional
handling. MinGW GCC static archives requesting 64-byte code alignment also
remain outside the checked stock-Go profile. Dynamic runtime profiles remain
available for those compilers.

### Platform reference

Each target family has its own producer reference:

- [Darwin](docs/darwin.md): the object profile and its unsupported inputs,
  linked dylib input with Objective-C and Swift registration, relocatable code
  with a dylib and `-wrap` of its binds, and implementation notes.
- [Linux](docs/linux.md): sysroots and system libraries, symbol versions and
  `-linux-max-symbol-version`, weak references, alignment and toolchain
  requirements, TLS (including opt-in `-linux-static-tls`), linked shared object
  input, and implementation notes.
- [Windows](docs/windows.md): COFF producer profiles, compiler flags, imports
  and CRTs, GNU Rust std, linked DLL input, relocatable code with a DLL and
  `-wrap` of its imports, and implementation notes.

### Distributing a generated package

Ship the complete generated package as a normal Go package. For typed
bindings, include its binding and bootstrap Go/assembly files, generated
headers, `.syso` objects, and bootstrap license/notice/provenance files; this
package needs no PureGo module requirement. For runtime registration, declare
`github.com/ebitengine/purego` in your module (verified at v0.11.3), alongside
the generated Go/assembly/`.syso` files. Consumers resolve that dependency
normally, including when your own Go API hides registration.

Document the target, binding mode, available functions or address-accessor
order, pointer ownership, and any required TLS finalization. Consumers build
typed packages with `go build` and runtime-registration packages with
`CGO_ENABLED=0 go build`, and need neither Rust nor the producer SDK. Retain the generated provenance and license/notice files in
both modes; see [licensing](#licensing). Windows lifecycle packages also include
`LICENSE-BAO-WINDOWS.txt` and `NOTICE-BAO-WINDOWS.txt`; retain these and all
`bao-linked-license-N.txt` files for bundled runtimes.

For Bazel consumers, provide a public `go_library` with the module's import
path and generated files in `srcs`. Include its `BUILD` files in the complete
module tree before signing. Consumer applications configure their own
`go_binary` and invoke the [Bazel verification backend](docs/signature-verification.md#bazel-consumer-builds).

### Signing library releases

A producer signs a complete Go module tree, including generated Go, assembly,
native objects, `go.mod`, included headers, embed data and Bao's provenance
files. Include Bazel `BUILD` files before signing a Bazel-native module.
All regular files are included; only root `.git` directory metadata is
excluded. Symlinks and special files are refused. Keep unrelated build trees,
caches, private keys and signed envelopes outside that module. The signature authenticates file
paths and SHA-256 content hashes, not ownership, executable bits or timestamps.

```sh
bao keygen -private /secure/release-key.pem -public /secure/release-public.pem
bao sign -root ./generated-module -module example.org/native \
  -target darwin/arm64 -release v1.2.3 \
  -key /secure/release-key.pem -o /release/native-darwin-arm64.json
```

### Go library packages

Library developers embedding Bao in their own producer or verification tools
can import its reusable packages directly from Go. The CLI uses these same
implementations:

| Import path | Purpose |
| --- | --- |
| `github.com/moriyoshi/bao/translate` | Darwin Mach-O inspection, TLS/import/unwind lowering, debug stripping and Go object encoding |
| `github.com/moriyoshi/bao/linuxelf` | Linux ELF translation plans, target sysroot validation and debug stripping |
| `github.com/moriyoshi/bao/pecoff` | Windows COFF member selection, import/initializer/unwind plans and debug stripping |
| `github.com/moriyoshi/bao/bindings` | Signature manifests, DWARF inference and fixed-signature binding generation |
| `github.com/moriyoshi/bao/toolchain` | Target detection and explicit Cargo/native-linker producer orchestration |
| `github.com/moriyoshi/bao/verify` | Signing, dependency scans, policy authentication and verified Go/Bazel builds |
| `github.com/moriyoshi/bao/ar` | General-purpose BSD/GNU archive parsing with ordered, zero-copy member views |

For example, infer a signature manifest from an optimized object with full DWARF:

```go
package main

import (
    "encoding/json"
    "log"
    "os"

    "github.com/moriyoshi/bao/bindings"
)

func main() {
    data, err := os.ReadFile("library.o")
    if err != nil {
        log.Fatal(err)
    }
    manifest, err := bindings.Infer("library.o", data, []string{"native_fn"})
    if err != nil {
        log.Fatal(err)
    }
    if err := json.NewEncoder(os.Stdout).Encode(manifest); err != nil {
        log.Fatal(err)
    }
}
```

Translation APIs consume native bytes and return lowered objects or plans;
assembling a complete generated Go package still requires the producer pipeline
described in [producing a Go package](#producing-a-go-package). `bindings.Generate` operates on an already staged Bao package.
Only `toolchain` producer operations invoke external compilers/linkers; signature
verification's `verify.Build` invokes a trusted Go toolchain and Bao executable;
`verify.Scan` invokes the offline Go module resolver, and `verify.BazelBuild`
invokes trusted Bazel and rules_go tools.
It retains the same explicit trust and fresh-cache requirements as
[`verified-build`](#consumer-controlled-signature-verification). `verify.Tool` is the subprocess hook for that
profile, not an independent link-only enforcement API. Bazel consumers can use
the public library targets `//translate`, `//linuxelf`, `//pecoff`, `//bindings`, `//toolchain`,
`//verify` and `//ar` (prefixed with their Bao repository name when used externally).

#### Reusable archive parser

`github.com/moriyoshi/bao/ar` is a standalone Go package within this module. It
imports only the standard library and reads ordinary Unix archives, including
BSD extended filenames, GNU long-name tables and Go package archives. It does
not invoke Bao's translator, native tools or verification policy.
COFF NUL-terminated long names are also supported. Its EC symbol index is
retained as opaque bookkeeping; the public parser preserves ordinary members
from every architecture and does not validate or select an ARM64EC ABI.

```go
members, err := ar.Parse(data) // data is the complete archive as []byte.
if err != nil {
    return err
}
for _, m := range members {
    if m.Kind == ar.Regular {
        fmt.Printf("%s: %d bytes, header at %d\n", m.Name, len(m.Data), m.Offset)
    }
}
```

The result preserves archive order and duplicate names, resolves BSD/GNU long
names, and retains symbol tables (`ar.SymbolTable`) and GNU filename tables
(`ar.NameTable`) as opaque payloads. `__.PKGDEF` remains a regular member.
Payload slices borrow the input with capacity limited to their length. Parsing
leaves the input untouched; copy a payload before changing it if the input must
remain immutable. Member names are metadata and are never opened as filesystem
paths. Extraction and writing are outside this API.

Parsing validates all member boundaries and returns no partial result on
failure. `*ar.ParseError` reports a byte offset; `errors.Is` distinguishes
`ar.ErrFormat`, `ar.ErrThinArchive` and `io.ErrUnexpectedEOF`. Odd stored sizes
require LF or NUL padding, counted before removing a BSD name prefix. GNU
name references are byte offsets bounded by the filename table; duplicate tables
are rejected. Thin archives are rejected without reading their external members.
Ownership, mode and timestamp fields and symbol-index contents are not decoded
or validated. This is a structural archive parser, not artifact authentication.

### Config files and diagnostics

`bao build` and `bao translate` can read their options from a JSON file with
`-config`. Without `-config`, Bao uses `.bao.config.json` from the working
directory if it exists and notes this on stderr. The file can name a linker
through `ld`, so review it before building in a checkout you do not trust.
`-v`, `-vv`, `-trace SYMBOL` and `-report FILE` report limits, unresolved
imports and other findings without changing the generated package. See
[config files and diagnostics](docs/config.md) for the keys, the diagnostic
output and finding IDs.

### Other commands

`bao inspect INPUT` reads ordinary BSD/GNU archives or Mach-O objects without
external tools and reports conservative raw-input compatibility as JSON.
`bao pack -o NEWDIR [-symbol NAME] INPUT` preserves bytes for a narrow,
self-contained subset with no runtime initialization. Its `packable` report is
about that subset, not the more capable `translate` pipeline.
Use `translate` for the maintained Darwin output.

### Independent examples

| Rust library | What it checks |
| --- | --- |
| CoreFoundation | Unicode string and binary property-list round trip |
| CoreGraphics | Bitmap drawing and exact RGBA bytes; floating-point/CGRect ABI |
| CoreText | Font glyph lookup and individual/summed advances |
| Security | Random bytes and exported framework data |
| ImageIO | In-memory PNG encoding, decoding and rendered pixel comparison |
| Foundation | NSString messages and autorelease pools through the ObjC runtime |
| Accelerate | Strided vector addition and dot product versus scalar Rust |
| Rust runtime + CoreFoundation | Caught panic, RAII cleanup, native threads, aligned TLS, TLS destructors, initializer ABI/order, data pointer fixups and addends |

See [Darwin example verification](docs/maintainers.md#darwin-example-verification) to run these checks.

[Darwin C++ lifecycle probes](examples/cpp/README.md) separately check exceptions,
128-byte-aligned TLS and destructors, static construction and explicit static
destruction. TLS/static cleanup works for the checked examples with a
producer-supplied DSO handle and explicit finalization. The tested C++ compact
exception metadata remains unsupported; Go process exit alone does not run
native static destructors or libc exit callbacks.
The [Linux C++ examples](examples/cpp_linux/README.md) pass exception/RAII
unwinding, TLS/destructors and explicit static cleanup with both GCC and Clang
using libstdc++ on arm64, amd64, loong64 and ppc64le. The cross-target results
use QEMU and require the Rust examples as CI/release gates.

## Bao maintainers and developers

You change Bao itself. This section covers its source build, CI, translator
implementation, verification suites, and embedded native runtime helpers.

### Building from source

Bazel 8.4.2 builds the CLI and tests using the pinned Go 1.26.11 SDK. Python is
not required. Native integration suites additionally need Rust/Cargo and a
compatible native linker/SDK or Linux sysroot.

```sh
bazel build //:bao
bazel run //:bao -- doctor
bazel run //:bao -- targets
bazel run //:bao -- help build
```

### Tests and native helpers

```sh
bazel test //...
bazel run //:verify -- -suite tls
bazel run //:verify -- -suite tls -target darwin/amd64
```

`bazel test //...` uses synthetic fixtures and needs no Rust compiler. The
integration suites run with `bazel run //:verify -- -suite NAME`:

| Suite | Checks | Details |
| --- | --- | --- |
| `tls` | Darwin TLV resolver registers, threads and destructors | [Tests and native helpers](docs/maintainers.md#tests-and-native-helpers) |
| `darwin` | The Darwin Rust examples, signed and unsigned | [Darwin example verification](docs/maintainers.md#darwin-example-verification) |
| `cpp` | C++ lifecycle probes against native controls | [C++ runtime verification](docs/maintainers.md#c-runtime-verification) |
| `static` | Bundled Rust and C++ runtimes | [Static runtime verification](docs/maintainers.md#static-runtime-verification) |
| `bindings` | Typed bindings, DWARF inference and stripping | [Binding verification](docs/maintainers.md#binding-verification) |
| `linux` | The Linux Rust runtime example in native arm64 Docker | [Linux verification](docs/maintainers.md#linux-verification) |
| `signatures`, `bazel` | Signed modules and verified Go and Bazel builds | [Tests](docs/signature-verification.md#tests) |

CI also runs the `linux-cross` and `windows` suites (`ci/check.sh`), and the
release workflow runs `release-smoke` on packaged CLIs. `bazel run //:verify --
-help` lists every suite.

Native helper regeneration (`bazel run //:native`), translation probes and
the runtime bootstrap's provenance are covered in
[maintaining Bao](docs/maintainers.md).

## FAQ

### Do application developers need Bao, Rust or a C/C++ compiler?

Consumers of a generated package need stock Go 1.26.11, the complete generated
package and compatible target system libraries. Ordinary application builds use
`go build` for typed packages, or `CGO_ENABLED=0 go build` for runtime
registration, and do not invoke Bao or a native compiler. An application with
its own cgo dependencies needs a working C compiler for them.
Library producers need the native toolchain when compiling or combining inputs. See
[consumer builds](#using-generated-go-packages) and
[package production](#producing-a-go-package).

### Can I use a Bao package with a third-party library that requires cgo?

Yes, with typed bindings generated by a current Bao and Go's internal linker
(`-ldflags=-linkmode=internal`). Dependencies that require external linking
remain unsupported, and the PureGo registration mode keeps its cgo-disabled
profile. See [consumer builds](#using-generated-go-packages),
[runtime compatibility](#compatibility-and-pointer-lifetimes) and
[platform support](#platform-support).

### Does CGO_ENABLED=0 mean native calls have no runtime transition?

Native calls still need a transition from Go to the native ABI and system stack.
Bao's generated typed adapters use the Go runtime's `cgocall` path; the runtime
registration mode uses PureGo. Neither mode requires a custom Go toolchain. See
[runtime support](docs/maintainers.md#runtime-support-and-boundaries).

### Is PureGo required?

The library producer chooses. Generated typed bindings need no PureGo module
dependency; Darwin/Linux typed packages bundle adapted bootstrap sources and
their notices. Runtime-registration packages require PureGo even when a Go
wrapper hides registration. A bundled bootstrap must be the only bootstrap
provider in the executable. See [binding modes](#choosing-a-binding-mode) and
[runtime compatibility](#compatibility-and-pointer-lifetimes).

### Is the resulting executable fully static?

Bao links the translated native code into the executable, while system libraries
remain dynamically linked through the OS loader. It does not extract a native
library at startup or allocate executable memory to load one. Linux profiles
require compatible glibc/system libraries; static musl is unsupported. See the
[Linux reference](docs/linux.md).
Fully static Bao executables with no shared-library dependencies are currently
unsupported on every target. Linux native-compiler controls pass fully static
linkage, but Bao's Go/native bootstrap still requires dynamic OS services.

### Can packages bundle language runtimes?

Yes. Rust std with its unwinder and C++ runtimes can be linked into the package
on macOS, Linux and Windows within checked profiles; OS libraries stay dynamic.
See [bundling language runtimes](#bundling-language-runtimes).

### Can I translate any Rust or C++ library?

Inputs must fit the target's supported object format, relocations and runtime
profile, with C ABI entry points. Use `extern "C"` exports or wrappers for Rust
and C++. Rust std/unwinding and C++ exceptions have platform-specific coverage;
Windows supports the documented C/C++ profiles and GNU Rust `std` with bundled
unwinding; the smaller Rust `no_std` fixture remains a separate gate.
Typed bindings
accept scalar signatures, with explicit pointer/length pairs for buffers. See
[platform reference](#platform-reference), [binding types](#explicit-declarations)
and the [Windows profile](#windows-amd64--arm64).

### Which platforms are supported, and can I cross-build?

See [platform support](#platform-support) for targets, input kinds and where
each has run. Consumers can select `GOOS` and `GOARCH` when the library supplies matching
generated files. Producers also need the target SDK/sysroot and a compatible
linker when combining archives. See [target builds](#building-for-the-target)
and [platform support](#platform-support) for verification limits.

### Why does a Darwin package contain ELF .syso objects?

The ELF relocatable container preserves section alignment through Go's internal
linker. Its machine code still uses the Darwin ABI, and the final executable is
normal Mach-O. These objects are not Linux libraries. See
[Darwin implementation details](docs/darwin.md#implementation-notes).

### Are native dependencies verified automatically by go build?

Ordinary `go build` does not invoke Bao's signature verification. Consumers can
explicitly run `bao verify` to scan downloaded dependencies or
`bao verified-build` to authenticate approved native modules and check actual
linker inputs. Both rely on independently trusted tools, policy and keys;
signatures do not establish that code is benign. See
[consumer-controlled verification](#consumer-controlled-signature-verification).

### Where does the name Bao come from?

Bao is named after both the steamed bun, a nod to wrapping native code for Go,
and Baryon Acoustic Oscillations (BAO).

There are a few playful parallels with the cosmological phenomenon. Sound waves
(not in the sense of real audio) in the early photon-baryon plasma left a pattern
in matter that astronomers can still measure after the waves stopped propagating.
Similarly, Bao's build-time translation leaves native code and runtime support in
the executable for later use.

## Licensing

Bao's implementation, native helpers and authored examples are Apache-2.0; see
[LICENSE](LICENSE). No loader implementation was copied from Go, dyld, Reflektor,
Binject or another project. Go's Mach-O parser is used through its public API.
The optional PureGo runtime mode uses a separate Apache-2.0 module. Generated
bindings bundle adapted Apache/BSD runtime-bootstrap sources with their notices
and licenses; see [function bindings](#function-bindings-and-native-debug-stripping).
Packaging does not change input licenses: distributors must carry the native library's
original licenses and notices, including those of Rust's standard library.
Hash manifests do not replace notices.
