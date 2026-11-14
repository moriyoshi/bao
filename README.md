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
[Linux arm64 / ELF](#linux-arm64--elf) and [Linux amd64 / ELF](#linux-amd64--elf).

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
cgo dependency, use the [internal linker](#using-generated-go-packages) and a C
compiler:

```sh
CGO_ENABLED=1 go build -ldflags=-linkmode=internal -o app .
./app
```

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
packages need no bootstrap. With Go 1.26.11, cgo-enabled builds without another
cgo dependency were executed on macOS arm64 (native) and amd64 (Rosetta 2),
Linux arm64 (native Docker), Linux loong64 and ppc64le (QEMU) and Windows amd64
(Wine). Linux amd64 was executed under emulation with the bootstrap alone, not
with a translated native library.

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
this flag or `CGO_ENABLED=0`. This path has been exercised with Go 1.26.11 on
macOS arm64 and amd64 (Rosetta 2), Linux arm64, Linux loong64 and ppc64le
(QEMU), and Windows amd64 under Wine with LLVM-MinGW; Linux amd64, native
Windows and other toolchains require separate verification.

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

See the library developer's [supported boundaries](#supported-boundaries)
and [Linux profile](#linux-arm64--elf) for platform limitations.

### Runtime caveats

#### compatibility and pointer lifetimes

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

### Windows amd64 / arm64

Use the supplied Go package with stock Go 1.26.11 and either generated typed
bindings or PureGo registration. C/C++ and GNU Rust std libraries are supported
within the [documented producer profiles](#windows-producer-reference).
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
Windows/386 and ARM64EC are unsupported. Current local checks use Wine; native
Windows CI remains a release gate. See [per-platform details](#per-platform-details)
for verification status and implementation notes.

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

#### Release metadata and policy

The library developer supplies a signed release envelope covering the complete
module, as described in [signing library releases](#signing-library-releases).
To use these optional verification commands, obtain a trusted Bao CLI from
[CLI releases](#cli-releases). Ordinary application builds do not require it.

A consumer pins the **key and exact payload digest**, module, release and target
in a policy received and approved through their independent trusted channel:

```json
{
  "schema": 1,
  "keys": {"PUBLIC_KEY_SHA256": "BASE64_RAW_ED25519_PUBLIC_KEY"},
  "approvals": [{
    "module": "example.org/native",
    "target": "darwin/arm64",
    "release": "v1.2.3",
    "key_id": "PUBLIC_KEY_SHA256",
    "payload_sha256": "EXACT_APPROVED_PAYLOAD_SHA256"
  }]
}
```

Placeholders are deliberately unusable; Bao ships no publisher key or release
authority. Fetching a replacement policy/key or blindly approving the latest
digest from a compromised publisher defeats this trust model. Exact approvals
prevent automatic acceptance of newer or older releases, including another
release signed by the same key. Policy rotation/revocation, freshness and
rollback decisions remain with the consumer. There is no TUF update service,
transparency-log integration, threshold policy or automatic key discovery.

#### Scan downloaded dependencies

```sh
bao verify -go /trusted/go1.26.11/bin/go -json
bao verify -C ./consumer -go /trusted/go1.26.11/bin/go \
  -policy /trusted/native-policy.json \
  -manifest /release/native-darwin-arm64.json -target darwin/arm64 -json
```

The default scope is the current module's dependencies, including downloaded
dependencies it does not import. Bao resolves the module build list offline,
runs `go mod verify`, and scans downloaded source trees for `.syso` files across
all targets and subdirectories. It checks complete trees against independently
approved signatures and rejects unsigned native dependencies. Ordinary Go
dependencies without native inputs need no Bao policy. Repeat `-manifest` for
multiple approved modules; supply policy and manifests together.

The main application module and unrelated entries in the global module cache
are excluded. Local replacements are scanned too, but Go's module-cache
integrity check does not cover them. Missing source downloads are reported as
`not-downloaded`, not fetched or authenticated; an approved native module that
is missing fails. Missing module metadata may prevent offline resolution, so
download dependencies beforehand. Source trees containing symlinks are refused.

Scanning compiles and runs no application code. It authenticates downloaded
sources at scan time and does not certify a later build or shared build cache.
Use `verified-build` to check actual linker inputs. JSON reports are also
printed on scan rejection, with a nonzero exit status.

#### Go build flow and cache boundary

Download ordinary Go dependencies before verification, then invoke:

```sh
bao verified-build -policy /trusted/native-policy.json \
  -manifest /release/native-darwin-arm64.json \
  -go /trusted/go1.26.11/bin/go -target darwin/arm64 -o ./app ./cmd/app
```

Repeat `-manifest` for independently approved native modules. The command:

1. Checks signatures and exact policy approvals on every request.
2. Resolves one executable's dependency closure using stock Go, with cgo,
   workspaces, module networking, toolchain downloads and Go environment files
   disabled. Dependencies must already be available. It never runs `generate`,
   consumer `init`, `main`, or functions inside untrusted native objects.
3. Copies selected module trees into a private temporary directory and checks
   the copied bytes against each approved manifest. It binds every selected
   `.syso` to an approved complete module; unsigned native inputs fail closed.
   Ordinary Go dependencies and consumer application code remain consumer
   trusted unless their modules are also explicitly approved. This does not
   authenticate the entire Go supply chain.
4. Rewrites only dependency resolution in the private main `go.mod` to those
   snapshots, resolves again and rejects packages escaping them. Read-only
   snapshots, scrubbed build environment, internal linking, and a **new empty
   private `GOCACHE` per invocation** prevent reuse of unverified shared build
   results. The initial profile has no verified-cache reuse optimization.
5. Uses a private `-toolexec` hook that keeps Go tool version probes working.
   Immediately before linking it parses the actual input package archives,
   checks native member digests and multiplicities, rejects unknown/substituted
   members, and gives the linker read-only private copies of those exact bytes
   through a rewritten `importcfg` and main archive path. It requires a linker
   verification report before publishing a new executable and reports archive
   and final-executable SHA-256 values. Existing output files are refused.

#### Bazel consumer builds

For a local rules_go consumer, select the separate Bazel backend:

```sh
bao verified-build -backend bazel -bazel /trusted/bin/bazel \
  -C ./consumer -module example.org/native=native \
  -policy /trusted/native-policy.json \
  -manifest /release/native-darwin-arm64.json \
  -target darwin/arm64 -o ./app //cmd/app:app
```

Each `-module importpath=relative/root` binds one approved complete native module
to a directory inside the consumer workspace, containing the library developer's
[prepared and signed package](#distributing-a-generated-package). Configure
the application's `go_binary` with `pure = "on"` and the requested
`goos`/`goarch`. Pin Bazel 8.4.2
(set the consumer's `.bazelversion` when using Bazelisk),
rules_go 0.65.0 and the downloaded Go 1.26.11 SDK, and generate the consumer's
`MODULE.bazel.lock` before verification. Consumer Bazel/Starlark definitions and
these tools are trusted; native repositories must be local signed roots.

Bao authenticates copied native source trees before Bazel loads their build
definitions, then analyzes a restricted action graph with rc files disabled.
It compiles into new private Bazel/Go caches with disk/remote action-result reuse
disabled, checks the actual link `.a` members, and replays the selected GoLink
action with private copies of those archives, standard-library archives, builder
and linker. rules_go's split export/archive format is checked separately from
stock Go's format. The consumer executable is published only after this checked
link completes; consumer `init` and `main` are never run by verification.

This initial backend accepts one local `//package:target` executable with pure
internal linking. External native repositories, custom build actions, cgo,
plugins, coverage/race modes, arbitrary compiler/linker flags and alternate
rules_go/SDK versions are refused. Repository/SDK downloads may occur in the
fresh private repository cache. This is a bounded rules_go profile, not a
general Bazel action sandbox or a `-toolexec` wrapper for Bazel.

#### Limitations

The consumer-controlled host, Bao executable, Go SDK/tools, main application,
unapproved Go dependencies and policy files are trusted. This does not defend
against root, a hostile process with the same user's privileges, memory or
toolchain compromise, or a signer approving malicious code. Private directories
and read-only copies reduce incidental mutation; they are not an OS security
sandbox against that user. The implementation does not claim race-proof checks
against a hostile same-user process. Archive copies bind the checked bytes to
the paths provided to the trusted linker within this host trust assumption.

The stock Go profile builds a single main package without custom flags, overlays,
workspace mode, external linking or shared-library inputs. It rejects native
objects in the standard library, and assembly includes escaping a selected
package. Native target support is inherited from the stock toolchain and Bao's
translator profiles. Verification itself requires no Rust compiler, Apple
linker, native extraction, cgo or execution of the consumer. Mac app codesigning
is a separate later step and does not prove prelink artifact identity.

Input source provenance, reproducibility, builder authorization and code review
are separate from authenticating bytes. Signed Bao provenance files are useful
records, not independent proof of how a producer built its artifacts. Module
checksums and `go mod verify` serve their documented module-cache roles; they
do not establish an independently approved native release signing authority.
See [Go build/tool execution](https://pkg.go.dev/cmd/go@go1.26.11),
[Go module verification](https://go.dev/ref/mod#go-mod-verify) and
[SLSA verification expectations](https://slsa.dev/spec/v1.2/verifying-artifacts).

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
[Windows producer reference](#windows-producer-reference). macOS SDK discovery uses `xcrun`, or pass
`-sdk`. Linux defaults to `/` only when the producer matches the target; cross translation needs
`-sysroot`. `-ld` selects a compatible cross linker. Combining Darwin archives
on another host requires a compatible Apple partial linker; precombined-object
translation itself needs no native compiler/linker.

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

### macOS dylibs

A linked arm64 or x86_64 dylib can be the input instead of objects or an
archive:

```sh
bao build -target darwin/arm64 -symbol python_entry -o ./py libpython3.13.dylib
```

A linked dylib reaches its data through PC-relative instructions without
relocations, so Bao keeps its image together and lets it run where Go links it:
- **Placement:** the image is one 16 KiB-aligned read-only section. Go's Darwin
  linker places such host sections in `__TEXT,__rodata`, inside the
  executable's `__TEXT` segment, so the dylib's code runs from signed pages of
  the executable. The image needs no link-time relocations.
- **Data pages:** the dylib's data segments are 16 KiB-aligned within the image,
  so they never share a page with its code. At initialization they are made
  read-write, fixed up, and `__DATA_CONST` is made read-only again. Code pages
  are never written.
- **Fixups:** chained fixups (`DYLD_CHAINED_PTR_64` and `_64_OFFSET`) or
  `LC_DYLD_INFO` rebase and bind opcodes; lazy binds are bound eagerly. Each
  bind resolves in the library its two-level namespace names, opened with
  `dlopen` by its install name. A missing weak import is null.
- **Library paths:** the dylib's code is part of the executable, so
  `@executable_path` and `@loader_path` both name the executable's directory,
  as dyld treats the main executable. `@rpath` tries the dylib's `LC_RPATH`
  entries in order, each expanded the same way. The libraries must exist there
  at run time, for example shipped next to the executable.
- **TLS:** thread-local variables use Bao's Darwin TLS runtime. The template is
  copied from the fixed-up image, so initializers may hold addresses, and each
  TLV descriptor's thunk is replaced.
- **Unwinding:** libunwind finds no compact unwind information for this code,
  so `__unwind_info` is converted to DWARF FDEs. That covers arm64
  `FRAME`/`FRAMELESS` and x86_64 `RBP_FRAME`/`STACK_IMMD`/`STACK_IND`,
  including personality and LSDA. The FDEs are registered with
  `__register_frame`, together with the dylib's own `__eh_frame` records.
- **Initializers:** `__mod_init_func` or `__init_offsets` run in order, after
  TLS is configured.
- **Objective-C:** libobjc learns about images from dyld, so the loader
  registers the dylib's metadata through libobjc's public API. It uniques
  selector references (`sel_registerName`), registers protocols (or uses an
  existing one of the same name), reads classes superclass-first with
  `objc_readClassPair`, attaches categories' methods and protocols
  (`class_replaceMethod`, `class_addProtocol`), and runs `+load` before the
  initializers. Categories on other images' classes work. Category properties
  and class properties are not attached.
- **Exports:** `SharedObjectExport(name)`, `SharedObjectExports()` and
  `-symbol` accessors return the image's addresses.

Not supported:
- arm64e dylibs, Swift images (libswiftCore registers images through dyld),
  and tagged or multi-start chained fixups.
- Relocatable code combined with a dylib.

`dladdr` reports the executable for the dylib's code, `__mod_term_func` does not
run, and weak definitions are not coalesced across images. Making the
`__TEXT` data pages writable has run only without the hardened runtime.

### Linux arm64 / ELF

`translate -target linux/arm64` handles native Linux AArch64 ELF64 relocatable code, independently
of the Darwin container workaround. It reads system exports from actual target
glibc/libgcc shared libraries in a producer sysroot. The final executable is
Linux ELF and uses the stock Go internal linker.

On a Linux arm64 producer, build from a Rust archive:

```sh
bao build -target linux/arm64 -sysroot / \
  -symbol bao_example_run -o ./native /path/to/libnative.a
```

The consumer needs Go, optional PureGo for runtime binding mode, and compatible target system libraries; it needs
neither the producer sysroot nor a native compiler. See
[using generated Go packages](#using-generated-go-packages) for consumer builds.

Imports normally resolve against the glibc and C++ runtime libraries. Name other
sysroot libraries with `-linux-system-library libxcb.so.1` (repeatable). Each
must exist in the sysroot, and it cannot replace a symbol the standard set
already exports. The consumer machine must provide the same library.

On every Linux target, an executable section aligned beyond 4096 bytes fails
translation by default. Stock Go's linker starts `runtime.text` at its 4 KiB
text address and then rounds the `.text` section up to the larger alignment,
so method offsets no longer match `runtime.text`. Interface method calls
through itabs built at run time then call the wrong function. Earlier packages
silently produced such binaries. libffi's AArch64 `trampoline_code_table`
(16 KiB) is one source. `-linux-max-text-alignment 4096` (or
`"max_text_alignment": 4096` in the `linux` config section) links these
sections at 4096 bytes, prints a notice and lists them under
`linux_capped_text_alignments` in bao-manifest.json and as
`BAO-ELF-TEXT-ALIGNMENT-CAPPED` in diagnostics. Code that depends on the
stronger alignment, such as libffi's static trampolines on kernels with pages
larger than 4 KiB, is unverified under the cap.

This path targets glibc/AArch64 and one combined native image. Other native TLS
models, native IFUNC definitions, preinit arrays and static musl are not
supported. A linked shared object is accepted as described in
[Linux shared objects](#linux-shared-objects). Other architectures use their
separate target profiles.

TLS initializers may hold absolute pointers to image data or system imports,
such as mimalloc's `__thread mi_heap_t *_mi_heap_default = &_mi_heap_empty`.
Bao writes them into its native TLS template before any thread copies it. A
pointer to another TLS variable, or any other relocation in a TLS template,
is rejected. This applies to every Linux target; it has run natively only on
arm64. Conditional and test-bit branches (`R_AARCH64_CONDBR19`,
`R_AARCH64_TSTBR14`), which Go's linker does not apply, are resolved during
translation when the target is in the same section; other targets fail
translation. Unreferenced local absolute symbols, such as OpenSSL perlasm
constants, are dropped; a relocation against an absolute symbol is rejected.

glibc keeps `atexit` in the static `libc_nonshared.a`, and its version loads
the value of `__dso_handle`, which Bao's private DSO identity does not
provide. Libraries that call `atexit` need a small wrapper such as
`int atexit(void (*f)(void)) { return __cxa_atexit((void (*)(void *))f, 0, &__dso_handle); }`.
Code built with AArch64 outline atomics (the default of many Linux GCC and
Clang toolchains) needs `__aarch64_cas*`/`__aarch64_ldadd*` helpers: pass
`-link-archive "$(gcc -print-libgcc-file-name)"` or compiler-rt builtins, or
build with `-mno-outline-atomics`. Missing optional weak imports have NULL address semantics and are
reported in the manifest; missing strong imports are rejected. Symbol version
requirements and other glibc/toolchain combinations need separate verification.
The [example README](examples/linux_runtime/README.md) records the final
pthread-destructor-pass boundary and process-lifetime libc bookkeeping after
explicit main-thread finalization.
`translate-elf` remains a compatibility alias; the `pack` and `probe-*`
commands remain available for low-level diagnostics.

On a native Linux host with the pinned Go SDK, GCC, binutils and a compatible
glibc sysroot, `sh ci/cgo-linux.sh` exercises fresh typed bindings with and
without cgo, including a separate cgo package and native TLS cleanup. Results
and generated inputs are left under `.work/`.

### Linux shared objects

On every Linux target (arm64, amd64, loong64 and ppc64le), a linked PIC shared
object, such as a distribution's `libpython3.13.so.1.0`, can be the input
instead of an archive:

```sh
bao build -target linux/arm64 -sysroot / -o ./py libpython3.13.so.1.0
```

To add relocatable code that calls the library, such as an `atexit` wrapper or
callback trampolines, pass that code as the input and the library with
`-linux-shared-object` (config key `linux.shared_object`). The input is combined
as usual and may reference the library's exports; the library's constructors
run first.

```sh
bao build -target linux/arm64 -sysroot / -symbol glue_run \
  -linux-shared-object libpython3.13.so.1.0 -o ./py libglue.a
```

The library's code reaches its data through PC-relative instructions that no
longer carry relocations, so Bao keeps its whole load image together as one
4 KiB-aligned executable section in Go's text. Dynamic relocations become
link-time pointers, init-time import fixups and Bao TLS descriptors. The
generated package makes the writable segments read-write, and not executable,
before native code runs, then makes RELRO read-only again after the fixups. It
runs `DT_INIT` and `.init_array` at package initialization; `FinalizeRuntime`
runs `.fini_array` and `DT_FINI`. The library's `.eh_frame` is registered in
place.

- Every default-version export (functions and data) is a native symbol that
  `-symbol` can select and the relocatable input can call.
  `SharedObjectExport(name)` returns any export's run-time address, and
  `SharedObjectExports()` lists the names.
- Functions from the library's `.symtab` are named in the executable's symbol
  table for tools such as `perf` and `addr2line`. Where Go's function lookup
  table would overflow, some names are left out; the manifest counts them.
- Versioned imports are bound with `dlvsym` to the version the library was
  linked against. glibc's compatibility versions of `exp`, `log`, `pow` and
  `pthread_kill` are different code from their current defaults. Translation
  fails if the sysroot lacks a required version.
- Imports resolve against the standard library set and
  `-linux-system-library`, as for archives. A `DT_NEEDED` library outside that
  set, such as `libutil.so.1` on an older sysroot, must be named.
- `bao-manifest.json` records the library under `shared_object`: its image
  size, writable and RELRO ranges, largest supported page size, relocation
  counts, versioned imports and exports.

The largest supported page size is the smallest distance between a writable
segment and executable code, at most 64 KiB, so that no page is both. GNU ld's
default maximum page size is 64 KiB on AArch64, LoongArch and PowerPC64, which
allows every page size those kernels use, and 4 KiB on x86-64, where the
fixture allowed 8 KiB pages. The generated package panics on a kernel with
larger pages.

Thread-local storage uses Bao's per-thread template:

| Target | TLS in the shared object |
| --- | --- |
| arm64 | TLS descriptors, the `-fPIC` default |
| amd64 | `__tls_get_addr` (the default) or GNU2 descriptors (`-mtls-dialect=gnu2`) |
| loong64 | `__tls_get_addr`, the default; `-mtls-dialect=desc` is rejected |
| ppc64le | `__tls_get_addr`; link with `-Wl,--no-tls-get-addr-optimize`, since `__tls_get_addr_opt` is rejected |

Initial-exec TLS, text relocations, IFUNCs and copy relocations are rejected,
as are PIEs and files without section headers. On ppc64le the image's
functions set up their own TOC from `r12` at their global entry point, so
relocatable input must call them through function pointers; a direct call is
rejected, because Go's linker has no cross-TOC call stubs. The
library's symbols bind within the image as `-Bsymbolic` would; nothing can
interpose them. Loading the library's own extension modules with `dlopen`
needs its exports in the executable's dynamic symbol table, which Bao does not
provide. The consumer must use Go's default build mode: the image's pointers
are applied in text, which `-buildmode=pie` leaves unrelocated, and the
generated package panics at initialization if it finds them so.

### Linux amd64 / ELF

`build -target linux/amd64 -sysroot /` accepts PIC ELF64 archives with a target
glibc sysroot and GNU linker. The checked C++ profile is GCC 14.4.0 or Clang
19.1.7 with GCC's libstdc++, glibc 2.41, GNU ld 2.44, checked with Go 1.26.10
and not yet rechecked with the pinned Go 1.26.11. It supports
exceptions caught inside C++, RAII cleanup, aligned TLS/destructors, native
constructors, imported data, and explicit static finalization in one combined
native image. Both runtime registration and DWARF-inferred assembly bindings
are checked. See the [Docker examples](examples/cpp_linux/README.md), which also
cover Linux arm64 with both compilers.

The amd64 TLS profile accepts general/local dynamic TLS with ordinary SysV
`__tls_get_addr` calls and GNU2 TLSDESC (`-mtls-dialect=gnu2`), including
local-dynamic `_TLS_MODULE_BASE_` sequences. TLSDESC calls enter a Bao thunk
that preserves the other general registers, flags, x87/MXCSR and XSAVE
AVX/AVX-512 state. GCC 14.2 and Clang 19.1.7 TLSDESC output has run only under
QEMU 10.0.13 (AVX2 and SSE-only CPU models); AVX-512 preservation is
unverified. Initial/local exec TLS (`R_X86_64_GOTTPOFF`, `R_X86_64_TPOFF32`)
is rejected: it assumes the image's TLS sits at a fixed offset from the
thread pointer, which Bao's per-thread blocks cannot provide. Native IFUNC
definitions, preinit arrays and static musl remain unsupported; linked shared
objects follow [Linux shared objects](#linux-shared-objects). Rust std is checked in the
[static-runtime profile](#can-linux-packages-bundle-c-and-rust-runtimes);
Clang with libc++ is unverified. Exceptions must stay inside native code;
Go process exit does not run C++ static destructors. Explicit TLS/static
finalization must follow the last native use. Local amd64 Docker verification
uses QEMU on an arm64 daemon; hosted CI selects a native amd64 runner.

### Supported boundaries

Linux loong64/glibc and ppc64le/glibc ELFv2 retain separate experimental
profiles. Their Rust runtime and typed-binding examples pass under QEMU 10.0.13
with Go 1.26.11. Both GCC 14.2 and Clang 19.1.7/libstdc++ C++ lifecycle suites
passed with Go 1.26.10 and have not yet been rechecked with Go 1.26.11. The
source CI gate requires Rust examples from the same cross image
before those C++ legs; release reuses the validated CI results. Physical LoongArch/PowerPC hardware
is unverified. See the [cross-image recipe](testdata/toolchains/README.md) and
[C++ checks](examples/cpp_linux/README.md).

The Darwin profiles use little-endian arm64 and generic x86_64 MH_OBJECT input, one combined native
runtime image per consumer executable,
Darwin C ABI exports and system imports available in the supplied v4 SDK text
stubs. Runtime verification is pinned to Go 1.26.11, Rust 1.99.1 and SDK 26.5.
Other versions require rerunning the checks. Input objects are trusted build
artifacts, not a hardened adversarial file format boundary.
TLS-free C/no_std libraries can use the runtime translation path as well.
`pack` retains its narrower byte-preserving leaf profile. Multiple separately
translated Rust std runtime images in one executable are not verified.

Unsupported inputs fail explicitly where recognized: arm64e objects, native
ObjC/Swift image metadata or class registration, indirect/stub sections,
unsupported segments/relocations, tentative common/absolute/indirect symbols,
TLS template relocations, TLS initializer callbacks, native terminator tables
without an explicit shutdown policy, compact unwind encodings
with personality/LSDA augmentation that cannot be synthesized, and custom
initializer ABIs requiring dyld's fourth/fifth arguments. Calling existing ObjC
classes through the runtime is exercised; Objective-C exception propagation
across Go is not supported. Native AppKit windows/input, Metal rendering,
notarization and general `go get` artifact distribution are unverified.

The amd64 profile uses baseline x86-64/SSE2. Its TLV thunk preserves the other
general registers, flags, x87 state and 128-bit XMM0–15; preservation of upper
AVX/AVX-512 lanes is unverified. Compact unwind supports RBP frames and existing
DWARF, and explicitly rejects frameless compact modes or unsupported augmentation.
Intel data-in-code annotations are retained as provenance while inline jump
table bytes remain in place. The eight examples and TLS register negative
control passed under Rosetta 2 on macOS/arm64 with Go 1.26.11. The first hosted
release rehearsal also passed on native macOS Intel before the current SDK
bump; that hosted check has not yet run with the new SDK. Exact toolchains and
results are recorded in [JOURNAL.md](JOURNAL.md).

### Windows producer reference

Produce ordinary COFF objects/archives for `windows/amd64` or `windows/arm64`.
Bao selects archive members itself and emits COFF `.syso` files for Go's internal
linker. A native partial linker is not required.

```sh
clang --target=x86_64-w64-windows-gnu -O2 -g -ffreestanding \
  -funwind-tables -c examples/windows_runtime/native.c -o native.obj
llvm-ar rcS native.a native.obj
bao build -target windows/amd64 -bindings dwarf -symbol bao_windows_run \
  -o ./native native.a
```

For ARM64, use `aarch64-w64-windows-gnu` and `windows/arm64`. MSVC and clang-cl
CodeView inputs require an explicit signature manifest; DWARF inference is
available for compatible Clang/GCC inputs. The checked MSVC C++ flags are
`/O2 /Z7 /MD /GS- /std:c++20 /EHsc /GR-`, plus
`/forceInterlockedFunctions-` on ARM64. Use the dynamic release CRT (`/MD`);
static/debug Microsoft CRT requests remain unsupported.

Use `-windows-cxx-runtime libc++` for LLVM-MinGW, or the default mapping for
MSVC/MinGW GCC. Dynamic C++ packages need the matching Microsoft runtime DLLs
or GNU C++/unwinder DLLs. Additional system functions require explicit
`-windows-import Function=system.dll` mappings or a producer-named
`-windows-import-library PATH` (repeatable). `-windows-crt ucrt` (default)
or `-windows-crt msvcrt` must match the native toolchain.

An import library such as LLVM-MinGW's `libuser32.a` supplies by-name
IMPORT_CODE records for names that are otherwise unbound. The first listed
library wins; `-windows-import` and Bao's built-in bindings take precedence.
Data, ordinal and wrong-machine records grant nothing. Import records inside the
native input or a `-link-archive` still grant no DLL binding. Each named library
is recorded by name and SHA-256 in `bao-manifest.json`.

Generated packages look up each system function when the package initializes. If
a function or its DLL is missing, the program still starts, and only a call to
that function prints its name to stderr and exits with status 2. That call cannot
be recovered from, because Go cannot unwind native frames. Functions that depend
on an activated assembly need it in the consumer: `TaskDialogIndirect`, for
example, requires a Common-Controls 6.0 application manifest. Imported data is
still resolved at startup and fails there, because it has no call to intercept.

Go's PE reader cannot provide data alignment above 32 bytes, so a section
requesting more fails by default. `-windows-max-data-alignment 32` links
read-only data sections at 32 bytes instead; writable data and code still fail.
This is an opt-in compromise: it breaks the alignment the native code declared,
so use it only when that code does not depend on the extra alignment, as with
tables aligned for cache behavior. Capped sections are listed under
`windows_capped_alignments` in `bao-manifest.json`, and the generated runtime
check enforces the applied value.

For GNU Rust std, the checked Rust 1.99.1 targets are
`x86_64-pc-windows-gnu` and `aarch64-pc-windows-gnullvm`, using
`panic = "unwind"`. Link the matching LLVM-MinGW static unwinder and CRT
compatibility wrappers. This Bash example includes the runtime notices:

```sh
export RUSTUP_TOOLCHAIN=1.99.1
rustup target add --toolchain 1.99.1 aarch64-pc-windows-gnullvm
runtime_prefix="$LLVM_MINGW/aarch64-w64-mingw32"
rust_docs="$(rustc --print sysroot)/share/doc/rust"
notices=(-link-notice "$LLVM_MINGW/LICENSE.TXT"
  -link-notice "$runtime_prefix/share/mingw32/COPYING.MinGW-w64-runtime.txt"
  -link-notice "$rust_docs/COPYRIGHT-library.html")
for license in "$rust_docs"/licenses/*; do notices+=(-link-notice "$license"); done
bao build -target windows/arm64 -manifest-path examples/windows_std/Cargo.toml \
  -locked -offline -bindings examples/windows_std/signatures.json \
  -symbol bao_windows_std_run -symbol bao_windows_std_check -symbol bao_windows_std_counts \
  -link-archive "$runtime_prefix/lib/libunwind.a" \
  -link-archive "$runtime_prefix/lib/libmingwex.a" \
  -link-archive "$runtime_prefix/lib/libucrt.a" \
  -require-static-runtime "${notices[@]}" -o ./native
```

For amd64, use `windows/amd64`, install `x86_64-pc-windows-gnu` and select the
`x86_64-w64-mingw32` prefix. Omit `-bindings` for PureGo registration.
See [bundling language runtimes](#can-packages-bundle-language-runtimes) for C++
archives and [examples/windows_std](examples/windows_std) for the complete std
fixture. The smaller `examples/windows_runtime` Rust crate uses `no_std`.

COFF weak aliases, common symbols and COMDAT selection are supported, including
`ANY`, `NODUPLICATES`, `SAME_SIZE`, `EXACT_MATCH`, `LARGEST`, `NEWEST` and
`ASSOCIATIVE`. Conflicting/malformed selection metadata is rejected. Ordinary
data alignment is limited to 32 bytes and code alignment to 16 bytes. TLS supports
alignment up to 8192 bytes and a 64 MiB template; unrecognized access forms and
TLS template relocations are rejected. Managed FLS keys must stay within the
image; destructor re-registration is bounded to four rounds. Native lifecycle
callbacks must not throw. Bigobj, ARM64EC and MSVC Rust targets remain unsupported.
Debug stripping retains runtime unwind metadata.

#### Windows DLLs

A linked 64-bit DLL can be the input instead of COFF objects:

```sh
bao build -target windows/amd64 -symbol python_entry -o ./py python313.dll
```

A linked DLL's code reaches its data through PC-relative instructions without
relocations, and Go's PE reader gives host code only function alignment, which
ARM64 page-relative addressing cannot use. So the generated package embeds the
DLL's prepared image and loads it at initialization into memory from
`VirtualAlloc`, as the Windows loader would:
- **Load steps:** base relocations; imports by name or ordinal, resolved with
  `LoadLibrary`; section protections; the DLL's function table, registered with
  its own base; TLS; then `DllMain(DLL_PROCESS_ATTACH)`.
- **Shutdown:** `Shutdown` calls `DllMain(DLL_PROCESS_DETACH)` and then the TLS
  callbacks.
- **Exports:** every export is reachable through `SharedObjectExport(name)` and
  `SharedObjectExports()`; `-symbol` selects exported functions for accessors
  and typed bindings.
- **Exceptions:** the DLL's exception handlers (SEH, MSVC C++, MinGW) work
  unmodified, because the registered function table gives them the DLL's base.
  RtlPcToFileHeader finds no module for private memory, which breaks MSVC's C++
  throw; Bao's helper replaces the DLL's imports of `RtlPcToFileHeader` and
  `_CxxThrowException` so the DLL's base is reported for its own addresses.
- **TLS:** implicit TLS uses Bao's helper storage. Each TEB TLS-array load in the
  DLL's code (`mov reg, gs:[0x58]` or `ldr xN, [x18, #0x58]`) is redirected to
  a thunk. It must be within 64 bytes of a PC-relative reference to the DLL's
  `_tls_index`, which the compiler's TLS sequence has; otherwise translation
  fails. TLS callbacks run with the DLL's base.

Not supported:
- 32-bit DLLs, .NET assemblies, writable executable sections, and DLLs without
  base relocations.
- Relocatable code combined with a DLL.
- Loading the DLL's own dependencies from inside the image: imports use the
  ordinary `LoadLibrary` search.

`DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` are not delivered, and the DLL has
no module handle: `GetModuleHandle` and `GetModuleFileName` do not know it, and
its `DllMain` receives its base as `HINSTANCE`.

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
`go_binary` and invoke the [Bazel verification backend](#bazel-consumer-builds).

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

`keygen` prints the public key as base64 plus its key ID (SHA-256 of the raw
Ed25519 public key). `sign` prints that ID and the signed payload's SHA-256.
Its envelope contains base64 `payload` and `signature` and a `key_id`.
The payload is JSON schema 1: `module`, exact `target`, `release`, and sorted
`files` entries containing `path` and `sha256`. Ed25519 signs the bytes
`bao.module-release.v1\0` followed by the exact payload bytes. Verification
does not reserialize or canonicalize untrusted JSON before checking a signature.

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

### Diagnostics

`build`, `translate` and `inspect` accept these flags; `doctor` accepts them for
its toolchain checks. They collect errors rather than only logging more: `-v`
keeps going within a stage and reports everything found there.

| Flag | Effect |
| --- | --- |
| `-v` | One line per stage with limits and headroom |
| `-vv` | Adds the symbols behind each number |
| `-trace SYMBOL` | SYMBOL's state at each stage; repeatable |
| `-report FILE` | Findings as JSON, for CI artifacts |
| `-assume-consumer net,crypto/x509` | Counts libraries those dependencies add |

```text
limits OK sections 25 / 65,279 (headroom 65,254)
imports FAIL 43 unresolved: xkb 29, xcb 14
imports HINT -linux-system-library libxcb.so.1 would satisfy 14
functions SKIPPED generation failed; no objects to measure
stopped: 1 failures; no package written
```

Diagnostics go only to stderr or the report file, and they do not change the exit
code or generated objects. Unresolved imports are listed together on every
platform, with or without `-v`. A stage that did not run prints `SKIPPED` with
the reason. A clean report means no known limit was exceeded; it does not verify
execution. The findfunc density is a prediction from object layout.

Findings have stable IDs: `BAO-ELF-SECTIONS`, `BAO-MACHO-SECTIONS`,
`BAO-COFF-SECTIONS`, `BAO-GO-FINDFUNC`, `BAO-MACHO-ORDINAL`,
`BAO-MACHO-FLAT-BIND`, `BAO-IMPORT-MISSING`, `BAO-COFF-ALIGNMENT-CAPPED` and
`BAO-GENERATE`.

`bao inspect -v -manifest bao-manifest.json ./program` reads a built Mach-O
executable, reports flat-namespace binds, and compares each bind's dylib with
the manifest. It exits non-zero on a failure. Library hints on Linux are advice:
binding still requires `-linux-system-library`. `-trace` reads each stage's
artifacts, so the translator stage it names is labeled as an inference.

### Config files

`bao build` and `bao translate` can read their options from a JSON file instead
of the command line:

```sh
bao build -config bao.json -target windows/amd64 -o ./native native.lib
```

```json
{
  "schema": 1,
  "package": "native",
  "symbols": ["native_add"],
  "bindings": {
    "schema": 1,
    "abi": "c",
    "functions": [
      {"name": "Add", "symbol": "native_add", "params": ["int64", "int64"], "result": "int64"}
    ]
  },
  "linux": {
    "sysroot": "${SYSROOT}",
    "system_libraries": ["libxcb.so.1"]
  },
  "windows": {
    "cxx_runtime": "libc++",
    "max_data_alignment": 32,
    "link_archives": ["${MINGW}/lib/libunwind.a"],
    "import_libraries": ["${MINGW}/lib/libuser32.a"]
  }
}
```

`bindings` is an inline manifest, a manifest path, or `dwarf`. Other top-level
keys are `target`, `input`, `strip_debug`, `strip_bitcode`, `link_archives`, `link_notices`,
`require_static_runtime` and `cargo` (`manifest_path`, `package`, `offline`,
`locked`). The `darwin` section takes `sdk`, `min_os` and `ld`; `linux` takes
`sysroot`, `ld`, `system_libraries`, `max_text_alignment` and `shared_object`; `windows` takes `imports`,
`import_libraries`, `cxx_runtime`, `crt` and `max_data_alignment`. Every platform
section also accepts `link_archives`, `link_notices` and
`require_static_runtime`.

Only the section for the build's target applies, and its link inputs follow the
common ones. Paths are relative to the config file and may use `${VAR}`; an
unset variable is an error. `${BAO_GOOS}`, `${BAO_GOARCH}` and `${BAO_CPU}` name
the build target, with `${BAO_CPU}` being `x86_64`, `aarch64` and so on, so
`${LLVM_MINGW}/${BAO_CPU}-w64-mingw32/lib/libuser32.a` serves both architectures.
They are not available in `input`, which can decide the target. A flag given on the command line replaces that whole
setting, including every entry of a repeatable flag. Unknown or duplicate keys
are errors, as is a setting the command cannot use. `-o` and the diagnostics
flags stay on the command line.

Without `-config`, Bao uses `.bao.config.json` from the working directory if it
exists and notes this on stderr. Parent directories are not searched. Use
`-config ''` to run without it. The file can name a linker through `ld`, so
review it before building in a checkout you do not trust.

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

See [Darwin example verification](#darwin-example-verification) to run these checks.

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

### Runtime support and boundaries

Pre-generated argument moves need a Go/native runtime transition. The adapters
use the pinned Go runtime's `cgocall` path to switch to the native system stack
and release the scheduler while native code blocks. They bundle adapted runtime
bootstrap sources from PureGo v0.11.3's `internal/fakecgo`, preserving its
Apache-2.0/Ebitengine and BSD/Go Authors notices. Generated packages carry both
license texts, a notice and upstream source hashes. The call adapters themselves
are Bao-authored. This removes the module/runtime-registration dependency; it
does not claim that all bootstrap code was independently reimplemented.

### Verification implementation

The [verified-build flow](#go-build-flow-and-cache-boundary) addresses Go's cache
caveat by construction. A standalone link hook can
be skipped entirely when Go reuses a cached build result. `packInternal` also
places `.syso` bytes into Go package archives inside `cmd/go`; there is no
external `pack` invocation to intercept. Checking original source paths at link
time would not authenticate a substituted cached archive.

The private `_verified-tool` command is an implementation detail, not a
supported mandatory verification hook for arbitrary `go build -toolexec` use.
The outer command's fresh cache and required linker report are essential.
These rules intentionally trade cache performance for a small trust model.

### Translation probes

`probe-lower-tlvp` and `probe-tls` expose explicitly incomplete diagnostic stages;
`probe-tls -runtime -format macho` cannot preserve stronger section alignment.
Use `translate` for the maintained Darwin output.

### Tests and native helpers

```sh
bazel test //...
bazel run //:verify -- -suite tls
bazel run //:verify -- -suite tls -target darwin/amd64
```

Default Go tests use synthetic fixtures and embedded runtime provenance hashes;
they need no Rust compiler or framework checkout. The `tls` suite additionally
checks all 128-bit SIMD lanes and required general registers across the native
TLV resolver, concurrent native threads, LIFO/reentrant destructors and a broken
register-restoration negative control. Native helper regeneration is a maintainer
action: `bazel run //:native`; sources, flags and hashes are recorded
under `translate/native/`.
Use `bazel run //:native -- -target darwin/amd64` for the Intel helpers.

Regenerate the Linux embedded native helper on Linux arm64 with
`bazel run //:native`.

### Darwin example verification

Run the explicit platform verification:

```sh
bazel run //:verify -- -suite darwin
bazel run //:verify -- -suite darwin -target darwin/amd64
```

The Go verifier builds each library through the CLI, translates it, makes a fresh Go executable with
cgo disabled and deliberately invalid native compiler paths, executes with
`GOMAXPROCS=1` and `4`, checks native alignment in the final executable, signs
with ad-hoc Hardened Runtime, strictly verifies the signature and runs again.
The Rust runtime case has an unwind-registration negative control. These
examples run headlessly. Dependency setup runs
`go get github.com/ebitengine/purego@v0.11.3` into the workspace cache; subsequent
consumer builds disable module networking. No local PureGo checkout or
`--purego-root` option is used. See the [development journal](JOURNAL.md) for
executed results and limitations; translation success alone is not an execution
claim.

### C++ runtime verification

```sh
bazel run //:verify -- -suite cpp -target darwin/arm64
bazel run //:verify -- -suite cpp -target darwin/amd64
```

The suite compares independent C++ executable controls with Bao consumers in
both binding modes, including signing and missing-initialization/finalization
negative controls. Its result is `CHECKED_WITH_LIMITATIONS`, preserving explicit
unsupported exception cases and any native TLS-alignment control failures.
See the [probe documentation](examples/cpp/README.md) for the exact scope and
producer adapter. Darwin CI runs this suite; release requires its validated
CI result and separately checks the packaged CLI.

For Linux, prepare the pinned compiler images and run `-suite cpp -target
linux/arm64` or `linux/amd64` with `-cxx g++` or `clang++` and the matching
`-image`. The [Linux recipe](examples/cpp_linux/README.md) gives complete
commands. Each Linux suite requires all five C++ cases, both binding modes,
unwind/lifecycle negative controls and scalar ABI checks to pass. Source CI
and the reusable release CI gate run both compilers on each architecture. For loong64
and ppc64le, use the maintained cross image and run the Rust runtime and typed
binding gates first, as shown in the Linux recipe. Their C++ suites use explicit
QEMU execution and the same image; C++ success alone does not pass the release gate.

### Binding verification

```sh
bazel test //bindings:bindings_test
bazel run //:verify -- -suite bindings -target darwin/arm64
bazel run //:verify -- -suite bindings -target darwin/amd64
```

The integration suite exercises explicit and inferred manifests, optimized debug
inputs, native debug stripping with EH retention, scalar/mixed/narrow values,
18 floating arguments, pointers, TLS and scheduler progress at GOMAXPROCS=1/4.
Darwin executables are also signed with ad-hoc Hardened Runtime and rerun. Rust
runtime checks retain panic, RAII, native threads and TLS destructors after
optimized DWARF inference and stripping, with an unwind-registration negative
control. Linux runs use the documented native arm64 or QEMU cross images.

### Linux verification

The independent [Linux runtime library](examples/linux_runtime/README.md) keeps
Rust std and panic unwinding and has no third-party crates. Its explicit harness
requires a native arm64 Linux Docker daemon and a Rust toolchain image:

```sh
bazel run //:verify -- -suite linux
```

The harness cross-builds a Go consumer on the host, then executes in native
Linux arm64 containers with a read-only filesystem, no network, and invalid
native compiler paths. Cross-linking alone is not counted as an execution pass.
The Docker image digest and tool versions are recorded in its evidence.

### Per-platform details

#### macOS (Darwin)

Bao lowers checked ARM64 TLVP or amd64 TLV address relocations while retaining per-thread
semantics through its native TLS resolver. The resolver copies an aligned
initialized/zero-fill template into per-thread native allocations, registers
LIFO/reentrant destructors and frees storage when a pthread exits. Native calls
use C ABI tail bridges; imported data pointers are fixed up in writable native
data before initialization. No executable pages are patched.

It preserves indexed local symbol identity, coalesces redundant same-address
text aliases, synthesizes supported section-boundary symbols and normalizes
relocation addends. DWARF FDEs are registered through Darwin's public
`__register_frame`. Supported compact unwind FRAME/FRAMELESS entries become
equivalent DWARF records; original native metadata remains in the artifact.
Constructors run in table order after imports, unwind and TLS setup, with native
`argc`, `argv` and `environ` on the startup OS thread.

The generated `.syso` files use **ELF relocatable containers for Darwin ABI
machine code** because Go's ELF object reader preserves section alignment that
its Mach-O reader omits. Go's stock internal linker accepts these inputs and
produces a normal Mach-O executable. This container choice is not Linux support
and is not a claim of compatibility with Apple's external linker. Applications
that link `runtime/cgo` through a cgo dependency still require Go's internal
linker.

#### Linux

Bao lowers Compiler TLSDESC sequences to image-private descriptors, native pthread
storage/destructors and a resolver that returns offsets relative to the native thread
pointer. Native DWARF chains are registered with libgcc's `__register_frame`.
Initializers run in numeric priority order with native copies of argv and libc's environ.
Imported data pointers are fixed up in writable native storage before constructors.

#### Windows (amd64 / ARM64)

Bao selects ordinary COFF archive members by exported functions and their native
dependencies, namespaces symbols and emits COFF `.syso` files for Go 1.26.11's
internal linker. System DLL calls use private IAT entries and function stubs.
Generated typed adapters use Win64 argument slots and shadow space on amd64,
or fixed scalar ARM64 registers, with Go's Windows `runtime.cgocall` transition.
This path needs no fakecgo bootstrap, native partial linker or runtime extraction.

CRT C initializers precede C++ constructors during package initialization. amd64 retains
`.pdata` for Go's PE exception directory and private native unwind/RTTI data;
ARM64 registers image-relative
function tables with `RtlAddFunctionTable`. DWARF inference precedes debug
stripping; MSVC/clang-cl CodeView inputs require explicit signature manifests.
Runtime unwind data is retained when debug information is stripped.

Compiler TLS uses image-private FLS storage and native thread cleanup. Dynamic
CRT/C++ exceptions, COMDAT selection with associated unwind data, function-local
statics, weak aliases and explicit `Shutdown()`
are supported within the detailed producer profile above. GNU Rust `std` with
bundled unwinding is checked separately in the static suite; MSVC Rust targets
and MSVC static/debug CRTs remain outside that profile. Native Windows VM
CI checks VC++, Clang and clang-cl on both architectures and MinGW on amd64;
Wine is a local aid only. Native Windows runtime verification remains pending. See
[Windows producer commands and boundaries](#windows-producer-reference)
for the complete profile, compiler flags and verification scope.

### Signature verification checks

```sh
bazel test //verify:verify_test
bazel run //:verify -- -suite signatures
bazel run //:verify -- -suite bazel -bazel /path/to/bazel
```

The integration fixture uses a freshly generated **local test key** and a Rust
leaf object produced once. Verification/build uses cgo disabled and unavailable
C/C++/Rust compiler paths. It tests an approved build and repeat request,
warm-shared-cache native substitution, altered generated Go/assembly, an extra
selected native object, wrong target/release, an invalid signature, and native
substitution inside a real cached package archive while its source stays
unchanged. Consumer initialization is checked absent until the approved binary
is deliberately run separately. The fixture currently runs on macOS/arm64.

The suite also authenticates and builds a complete generated static-binding
module, including its bundled runtime bootstrap, without a PureGo dependency.
Assembly archive names truncated to the same 16-byte prefix are verified with
their expected multiplicities; extra and missing members remain rejected.
The signature suite also scans an actual downloaded module cache offline,
rejects an unused unsigned native dependency and a modified cache entry, and
reports a dependency whose sources have not been downloaded.

The Bazel suite builds an independent local consumer on macOS arm64. It poisons
an ordinary shared native archive, verifies and links from fresh private state,
and rejects changed signed sources and a reachable custom action. The approved
executable is run separately. Linux arm64's Bazel consumer has also been checked
in native Docker execution; other Bazel target combinations need separate
validation. Test signing keys are local fixtures, not release authority.

### Archive parser checks

Bao uses a small private adapter in `internal/ar` to select regular members for
native object inspection and signature-input checks. That selection is separate
from the public parser. Run its tests with
`bazel test //ar:ar_test //internal/ar:ar_test` or `go test ./ar ./internal/ar`.

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

Yes, with newly generated typed bindings and Go's internal linker:

```sh
CGO_ENABLED=1 go build -ldflags=-linkmode=internal
```

Regenerate older packages with the updated Bao. Dependencies that require
external linking remain unsupported; the default cgo-enabled link fails on
supported examples. This path was executed with Go 1.26.11 on macOS arm64 and
amd64 (Rosetta 2), Linux arm64, Linux loong64 and ppc64le (QEMU) and Windows
amd64 under Wine. Windows arm64 was cross-linked but not executed; Linux amd64
and native Windows require separate verification. Without another cgo
dependency, no flag is needed.
The PureGo registration mode retains its cgo-disabled profile. See
[consumer builds](#using-generated-go-packages) and
[runtime compatibility](#compatibility-and-pointer-lifetimes).

### Does CGO_ENABLED=0 mean native calls have no runtime transition?

Native calls still need a transition from Go to the native ABI and system stack.
Bao's generated typed adapters use the Go runtime's `cgocall` path; the runtime
registration mode uses PureGo. Neither mode requires a custom Go toolchain. See
[runtime support](#runtime-support-and-boundaries).

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
[Linux arm64](#linux-arm64--elf) and [Linux amd64](#linux-amd64--elf) profiles.
Fully static Bao executables with no shared-library dependencies are currently
unsupported on every target. Linux native-compiler controls pass fully static
linkage, but Bao's Go/native bootstrap still requires dynamic OS services.

### Can packages bundle language runtimes?

Yes, with the following checked profiles. OS libraries remain dynamic throughout.

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

On macOS, `ci/darwin-static-runtime.sh arm64` (or `amd64`) builds the pinned LLVM
23.1.5 runtime profile and preserves its notices. It requires Git, CMake, Make
and the macOS SDK on the producer. Link `lib/libc++.a` for C++, or
`lib/libunwind.a` alongside a Rust staticlib, from the resulting
`.work/static-runtimes/darwin-ARCH` prefix. C++ exceptions remain unsupported;
Rust catch/unwind, aligned TLS, allocation, explicit C++ finalization and signed
execution are checked. Typed consumers without another cgo dependency need no
native compiler.

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

Run `bao-verify -suite static -target darwin/ARCH -static-runtime-root PREFIX`
or add `-windows-driver clang -windows-cc CC -windows-cxx CXX` for Windows.
These maintained suites gate C++ checks on fresh Rust checks and audit both
generated packages and executable dependencies. CI invokes the same suites on
macOS and native Windows. See the following Linux recipe for its Docker suite
and shutdown requirements.

### Can Linux packages bundle C++ and Rust runtimes?

Yes, within the checked glibc profile on arm64, amd64, loong64 and ppc64le.
`bao build` can search extra static archives for the native library's unresolved
references. For example, on a matching Linux arm64 GNU producer:

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

`-require-static-runtime` rejects known shared C++/Rust/unwinder library imports,
including imports introduced by generated registration code. It checks declared
imports, not arbitrary native `dlopen` behavior. The checked final executables
retain dynamic OS dependencies (`libc`, pthreads and dynamic lookup); this flag
does not make a fully static executable or authenticate third-party inputs.

Generated Linux packages expose `FinalizeRuntime()` to run retained ELF fini
arrays once, in reverse entry and priority order. Stop and join native workers,
then complete caller TLS cleanup and explicit C++ shutdown in the library's
required order before calling it. Caller TLS cleanup must run on its locked OS
thread. This function does not replace C++ shutdown,
run automatically at Go process exit, or permit subsequent native use or image
unloading. `FinalizeRuntime` is a reserved binding name. Use one combined native
runtime image per executable; exceptions must remain within native frames.

The maintained `-suite static` checks fresh Rust and C++ inputs with both binding
modes, dependency audits and lifecycle negative controls. Local arm64 execution
was native; amd64, loong64 and ppc64le used QEMU. Ordinary compiler-produced fully
static controls also ran, but Bao's current Go/native bootstrap still requires
dynamic glibc/pthread/loader support. Those controls are separate from Bao support.

### Can I translate any Rust or C++ library?

Inputs must fit the target's supported object format, relocations and runtime
profile, with C ABI entry points. Use `extern "C"` exports or wrappers for Rust
and C++. Rust std/unwinding and C++ exceptions have platform-specific coverage;
Windows supports the documented C/C++ profiles and GNU Rust `std` with bundled
unwinding; the smaller Rust `no_std` fixture remains a separate gate.
Typed bindings
accept scalar signatures, with explicit pointer/length pairs for buffers. See
[supported boundaries](#supported-boundaries), [binding types](#explicit-declarations)
and the [Windows profile](#windows-amd64--arm64).

### Which platforms are supported, and can I cross-build?

The maintained Darwin targets are arm64 and amd64. Linux has separate arm64,
amd64, experimental loong64 and experimental ppc64le profiles. Windows amd64
and arm64 are supported within their documented compiler and runtime profiles;
the current implementation's native Windows CI results are still pending.
Consumers can select `GOOS` and `GOARCH` when the library supplies matching
generated files. Producers also need the target SDK/sysroot and a compatible
linker when combining archives. See [target builds](#building-for-the-target)
and [supported boundaries](#supported-boundaries) for verification limits.

### Why does a Darwin package contain ELF .syso objects?

The ELF relocatable container preserves section alignment through Go's internal
linker. Its machine code still uses the Darwin ABI, and the final executable is
normal Mach-O. These objects are not Linux libraries. See
[Darwin implementation details](#macos-darwin).

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
