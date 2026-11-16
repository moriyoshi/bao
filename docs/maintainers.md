# Maintaining Bao

Details behind the commands in
[Bao maintainers and developers](../README.md#bao-maintainers-and-developers).

## Runtime support and boundaries

Pre-generated argument moves need a Go/native runtime transition. The adapters
use the pinned Go runtime's `cgocall` path to switch to the native system stack
and release the scheduler while native code blocks. They bundle adapted runtime
bootstrap sources from PureGo v0.11.3's `internal/fakecgo`, preserving its
Apache-2.0/Ebitengine and BSD/Go Authors notices. Generated packages carry both
license texts, a notice and upstream source hashes. The call adapters themselves
are Bao-authored. This removes the module/runtime-registration dependency; it
does not claim that all bootstrap code was independently reimplemented.

## Translation probes

`probe-lower-tlvp` and `probe-tls` expose explicitly incomplete diagnostic stages;
`probe-tls -runtime -format macho` cannot preserve stronger section alignment.
Use `translate` for the maintained Darwin output.

## Tests and native helpers

Default Go tests use synthetic fixtures and embedded runtime provenance hashes;
they need no Rust compiler or framework checkout. The `tls` suite additionally
checks all 128-bit SIMD lanes and required general registers across the native
TLV resolver, concurrent native threads, LIFO/reentrant destructors and a broken
register-restoration negative control. Native helper regeneration is a maintainer
action: `bazel run //:native`; sources, flags and hashes are recorded
under `translate/native/`.
Use `bazel run //:native -- -target darwin/amd64` for the Intel helpers.

Regenerate the Linux helpers with `bazel run //:native -- -target linux/ARCH`
for arm64, amd64, loong64 and ppc64le, and the Windows helpers with
`-target windows/amd64` or `windows/arm64`, which need Clang. Linux cross
targets need the matching GNU compiler and linker, such as those in the maintained
[cross image](../testdata/toolchains/README.md). Each target writes its blob and
`manifest.json` under `linuxelf/native/` or `pecoff/native/`.

## Darwin example verification

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
`--purego-root` option is used. See the [development journal](../JOURNAL.md) for
executed results and limitations; translation success alone is not an execution
claim.

## C++ runtime verification

```sh
bazel run //:verify -- -suite cpp -target darwin/arm64
bazel run //:verify -- -suite cpp -target darwin/amd64
```

The suite compares independent C++ executable controls with Bao consumers in
both binding modes, including signing and missing-initialization/finalization
negative controls. Its result is `CHECKED_WITH_LIMITATIONS`, preserving explicit
unsupported exception cases and any native TLS-alignment control failures.
See the [probe documentation](../examples/cpp/README.md) for the exact scope and
producer adapter. Darwin CI runs this suite; release requires its validated
CI result and separately checks the packaged CLI.

For Linux, prepare the pinned compiler images and run `-suite cpp -target
linux/arm64` or `linux/amd64` with `-cxx g++` or `clang++` and the matching
`-image`. The [Linux recipe](../examples/cpp_linux/README.md) gives complete
commands. Each Linux suite requires all five C++ cases, both binding modes,
unwind/lifecycle negative controls and scalar ABI checks to pass. Source CI
and the reusable release CI gate run both compilers on each architecture. For loong64
and ppc64le, use the maintained cross image and run the Rust runtime and typed
binding gates first, as shown in the Linux recipe. Their C++ suites use explicit
QEMU execution and the same image; C++ success alone does not pass the release gate.

## Static runtime verification

```sh
bazel run //:verify -- -suite static -target darwin/ARCH -static-runtime-root PREFIX
bazel run //:verify -- -suite static -target linux/ARCH -image bao-ci-cross
```

For Windows, add `-windows-driver clang -windows-cc CC -windows-cxx CXX`.
These maintained suites gate C++ checks on fresh Rust checks, check fresh Rust
and C++ inputs with both binding modes, and audit both generated packages and
executable dependencies, with lifecycle negative controls. CI invokes the same
suites on macOS, Linux and native Windows; `ci/check.sh` has the exact
invocations. Local Linux arm64 execution was native; amd64, loong64 and ppc64le
used QEMU. Ordinary compiler-produced fully static controls also ran, but Bao's
current Go/native bootstrap still requires dynamic glibc/pthread/loader
support. Those controls are separate from Bao support.

## Binding verification

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

## Linux verification

The independent [Linux runtime library](../examples/linux_runtime/README.md) keeps
Rust std and panic unwinding and has no third-party crates. Its explicit harness
requires a native arm64 Linux Docker daemon and a Rust toolchain image:

```sh
bazel run //:verify -- -suite linux
```

The harness cross-builds a Go consumer on the host, then executes in native
Linux arm64 containers with a read-only filesystem, no network, and invalid
native compiler paths. Cross-linking alone is not counted as an execution pass.
The Docker image digest and tool versions are recorded in its evidence.

On a native Linux host with the pinned Go SDK, GCC, binutils and a compatible
glibc sysroot, `sh ci/cgo-linux.sh` exercises fresh typed bindings with and
without cgo, including a separate cgo package and native TLS cleanup. Results
and generated inputs are left under `.work/`.

## Archive parser checks

Bao uses a small private adapter in `internal/ar` to select regular members for
native object inspection and signature-input checks. That selection is separate
from the public parser. Run its tests with
`bazel test //ar:ar_test //internal/ar:ar_test` or `go test ./ar ./internal/ar`.
