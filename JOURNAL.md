# Development journal

Development and verification notes, with recent work first. Markdown reports
were consolidated here before the generated `evidence/` directory was removed.
The outcomes, limits and historical context remain below; raw JSON exports,
logs and audits are no longer kept in the repository. Recorded scratch paths
and log filenames identify past runs, not permanent artifact locations.

## Generated bindings, optimized DWARF inference and stripping — 2026-11-08

Both consumer modes are implemented. Runtime mode keeps the purego address API.
Generated mode accepts an explicit scalar C ABI function manifest or infers one
from full debug DWARF, and emits typed Go plus assembly with no consumer module
dependencies. It bundles the licensed Apache/BSD fakecgo bootstrap from purego
v0.11.3 with original notices and source hashes; the call adapters are Bao-authored.
See [function bindings](README.md#bindings) for the format, compiler options and boundaries.

Final generated-binding checks pass on all five targets:

| Target | Result | Execution |
| --- | --- | --- |
| Darwin arm64 | PASS | Native macOS arm64, signed reruns |
| Darwin amd64 | PASS | Rosetta 2, signed reruns |
| Linux arm64 | PASS | Native arm64 Linux container |
| Linux loong64 | PASS | QEMU user-mode LP64D |
| Linux ppc64le | PASS | QEMU user-mode ELFv2 |

Optimized C with full DWARF exercises mixed/narrow scalar arguments, 18 floating
arguments (including actual stack spills on every target), opaque pointers,
uint32 extension, TLS and Go scheduler progress during a native blocking call
at GOMAXPROCS=1/4. Pointer arguments are pinned before encoding native addresses
and kept alive through the call. Go module/dependency checks confirm no purego
module in generated consumers. Full optimized Rust std inference and stripping
also preserve caught panic, two RAII drops, eight native threads and nine TLS
destructors with live=0/freed=9. Darwin's missing-registration negative control
still links but aborts during panic; all original native source inputs remain
unchanged.

`build`/`translate` strip native debug data by default after inference; EH frames,
compact unwind and exception tables remain. Apple's partial linker can replace
DWARF with STABS: Cargo inference therefore runs on original archive members,
and Bao removes the resulting debug symbol records (13,627 in the arm64 Rust
runtime check), even when no DWARF sections remain in the combined object.
`bao-debug.json` records removed sections/symbols and before/after hashes.
Unit fixtures include optimized C/C++/Rust Mach-O and ELF plus abstract-origin,
specification, missing-type, conflicting-type, variadic/aggregate/callback,
calling-convention and stripped-debug negative controls.

These function manifests describe C ABI types. They are distinct from signed
release envelopes. DWARF does not prove Rust `extern "C"`; selected exports assert
that ABI. External debug companion files, aggregates/variadics and generated Go
callbacks are outside the initial scalar profile. Use one bootstrap provider
per executable; mixing bundled providers with purego/runtime-cgo is unsupported.
Physical Intel/LoongArch/PowerPC hardware remains unverified.

`bazel test //...` passes all seven test packages; `go vet ./...` passes.
The runtime-purego regression suites also pass after these changes:
macOS arm64/TLS/native Linux arm64
and all eight macOS amd64 examples.
Final signature/cache controls
accept both consumer modes and count legitimately colliding 16-byte Go assembly
archive member names while rejecting extra/missing or substituted payloads.

## Additional architectures and independent verification — 2026-11-08

All new consumers use stock Go 1.26.5 with `CGO_ENABLED=0`. No Go toolchain
patch, runtime native extraction, or consumer native compiler is involved.

| Target | Execution evidence |
| --- | --- |
| macOS/amd64 | Eight independent framework/Rust libraries, Cargo/archive/object paths, unwind negative control, ad-hoc Hardened Runtime signing and reruns; Rosetta 2 on macOS/arm64 |
| macOS/amd64 TLV ABI | Concurrent TLS and register checks, full 128-bit XMM lanes, required GPRs, LIFO/reentrant destructors, broken SIMD-restoration negative control |
| Linux/loong64 | Full independent Rust std runtime, QEMU user-mode, GOMAXPROCS=1/4, unwind negative control, final section alignment and W^X audit |
| Linux/ppc64le | Full independent Rust std runtime, ELFv2, QEMU user-mode, GOMAXPROCS=1/4, unwind negative control, final section alignment and W^X audit |

Both new Linux legs catch a Rust panic, drop two RAII guards, join eight native
threads, run nine TLS destructors and free all nine blocks. They retain original
TLS state/address during late pthread cleanup and exercise constructors/argv,
libc callbacks, imported data and 128-byte static/TLS alignment. The LoongArch
path lowers checked CALL36 sequences to B26 plus a retained NOP, avoiding a
stock Go backward-call encoding problem without changing instruction span.
It also lowers unsupported relative metadata expressions to writable native
data fixups before unwind registration; executable code remains non-writable.
PowerPC handles checked GD/LD TLS and ELFv2 TOC/local entry behavior.
Physical Intel/LoongArch/PowerPC target hardware is not verified. Darwin amd64
AVX upper lanes and frameless compact unwind remain outside the checked profile.

The Bao-owned [signature facility](README.md#verification) authenticates complete generated
modules under consumer-pinned Ed25519 keys and exact release approvals. It uses
private source snapshots, a fresh private build cache per request and checks the
actual native members inside linker input archives. Its tests include native
byte changes with a warm shared cache, generated Go/assembly changes, extra
native inputs, bad signatures, wrong target/release, and substitution inside a
real cached Go archive while the source object stays unchanged. Consumer init
is absent during verification; the approved executable is run separately.
Local test keys establish no production publisher authority. Trusted host,
verifier, Go SDK, policy and ordinary unapproved Go dependencies remain explicit
assumptions; this is not a same-user hostile-process sandbox or a standalone
link-hook guarantee.

An additional complete amd64 Rust std consumer
also passes `verified-build` with its entire main module approved, then runs
separately under Rosetta with caught panic and all nine TLS blocks freed.
The complete existing macOS arm64/TLS/native Linux arm64 regression suite was
rerun after the architecture changes and
passes.

## Bazel and CLI migration — 2026-11-08

The primary workflow is Python-free. Bazel 8.4.2 with rules_go 0.65.0 builds the
CLI, verifier and native-helper generator using the pinned Go 1.26.5 SDK.
`bazel test //...` passes all five unit-test packages. The CLI provides Cargo,
archive and combined-object workflows, target selection, doctor, help/version,
JSON output, failure cleanup and refusal to overwrite existing output.

Verification fetches `github.com/ebitengine/purego@v0.11.3` with `go get`;
generated consumers use the normal module requirement and go.sum, without a
local replacement or `--purego-root`. The pinned module checksum is
`h1:OB+JLpdm7ioymhyA+6s5kbb/uOuYycAgL8NNTFc5MLg=`. Consumer builds then disable
module networking and use invalid native compiler paths.

```sh
bazel build //:bao
bazel test //...
bazel run //:verify -- -suite all
bazel run //:native
```

The Go verifier retains all eight Darwin framework/runtime cases, Cargo/archive/
object CLI paths, signed reruns, unwind-registration negative controls, full
SIMD/GPR TLS ABI checks, concurrent TLS/LIFO/reentrant destructor stress, and
actual native Linux arm64 Docker execution.
The optional headless GPUI integration is a separate `-suite gpui -gpui-root PATH`
check. Native framework SDKs and Rust/Cargo remain producer prerequisites;
Python is not required by the build or verification workflow.

## Historical verification — 2026-11-07

The commands below record the original runs. Their Python scripts and local
purego option have been retired; use the Bazel commands above to reproduce the
maintained checks. The original outcomes are summarized below.

The primary verification is independent of gpui-go: **eight self-contained Rust
static libraries translate, link with stock Go and `CGO_ENABLED=0`, and execute
on macOS/arm64**. Every executable passes ad-hoc Hardened Runtime signing,
strict signature verification and another execution. Native AppKit windows/input
and notarization are not verified. Linux arm64 also passes native execution through a separate ELF pipeline.

Final uncached Go tests with cgo disabled, Go vet, Rust formatting checks for
both workspaces, and Python syntax checks all passed. The run also recorded
tool versions and a source hash snapshot.

## Independent framework suite

Executed with Go 1.26.5, Rust 1.99.1 and macOS SDK 26.5:

```sh
python3 scripts/verify_examples.py \
  --purego-root /Users/moriyoshi/Source/gwigwi/build/go-mod/github.com/ebitengine/purego@v0.11.3
```

All eight Cargo packages have no third-party Rust dependencies and keep the
unwind panic strategy. The maintainer script compiles their static archives,
combines members using Apple's `ld -r`, translates with Bao, and builds fresh
consumer executables. Consumer `CC`, `CXX` and `RUSTC` deliberately point to
nonexistent paths; module networking is disabled. No GPUI source, archive,
package or build cache is required by this suite.

| Library | Executed native check | Result |
| --- | --- | --- |
| CoreFoundation | Unicode CFString -> binary property list -> equal decoded string | PASS |
| CoreGraphics | Draw rectangle and compare every RGBA pixel; native floating-point and CGRect arguments | PASS |
| CoreText | Map real Helvetica glyphs; sum individual glyph advances and compare total | PASS |
| Security | Fill native buffers through SecRandomCopyBytes/kSecRandomDefault | PASS |
| ImageIO | In-memory PNG encode/decode; correct dimensions and exact pixels after rendering | PASS |
| Foundation | Typed ObjC messages for NSString uppercase/UTF-8/length with an autorelease pool | PASS |
| Accelerate | Strided vDSP vector addition and dot product match scalar Rust | PASS |
| Rust runtime + CoreFoundation | Initializers, imports, pointer addend, alignment, panic cleanup, native threads and TLS lifecycle | PASS |

Each ran with `GOMAXPROCS=1` and `4`, then after ad-hoc Hardened Runtime signing.
The final Mach-O executable's retained native sections were audited against ELF
input section alignments: 21 sections in each framework case, 22 in the runtime
case. The latter retains actual 128-byte static storage and a 128-byte TLS
allocation; its checks use real runtime addresses rather than constant folding.

The standalone runtime archive contains 13 TLS descriptors, two initializers,
1,582 original FDEs, 1,301 synthesized compact unwind FDEs, 202 system imports and
one native data-pointer fixup. It verifies:

- Native initializer table order and startup-thread argc/argv/environ.
- Imported data address and an interior-pointer addend of seven bytes.
- Eight `std::thread` workers with initialized/zero-filled isolated TLS and Drop.
- Main-thread TLS finalization: nine destructors, nine released blocks, zero live.
- A Rust panic caught inside Rust with two RAII cleanup drops; no unwind crosses Go.
- A separate consumer with identical native objects but FDE registration disabled
  still links, then aborts at the panic. The test requires the expected unwind
  diagnostic and absence of a pass marker.

The normal panic hook prints the intentional panic before `catch_unwind` catches
it; this is expected in successful runtime logs. Random bytes are an API smoke
check, not a cryptographic quality assessment. The Foundation case uses existing
system classes; no custom ObjC image registration is claimed.

The run recorded executable/archive hashes, build information and native
alignment audits. Large generated archives, `.syso` packages and signed
executables were generated in
`.work/examples-verify-1omqyd6k/`. Each generated package has `bao-manifest.json`
with artifact hashes and its actual transformation plan.

## Native Linux arm64 / ELF

The separate `translate-elf` implementation passed the standalone
[Linux runtime library](examples/linux_runtime/README.md) on a native Linux
arm64 Docker daemon. This is actual target execution, not just a cross-link.
The producer uses the pinned Rust 1.99.1 Debian 12 image; stock Go 1.26.5 on the
host cross-builds the consumer with `CGO_ENABLED=0` and deliberately invalid
native compiler paths. Containers execute with a read-only filesystem and no
network, at `GOMAXPROCS=1` and `4`.

The native checks pass: caught panic with two RAII drops; eight std threads with
isolated initialized/zero-filled and 128-byte-aligned TLS; nine TLS destructors;
all nine image TLS blocks freed; zero live blocks; initializer numeric order and
argc/argv/environ; `std::env::args_os`; imported libc data and an interior pointer
addend; malloc/free; getpid; and a native Rust callback invoked by libc qsort.
An independent pthread key verifies that later cleanup still sees the original
TLS address, modified values and destroyed guard state.

The image has 11 TLS descriptors, 179 system imports, one imported-data fixup and
five initializers. All 6,693 retained native section addresses meet their input
alignment. The final Linux ELF has no writable/executable load segment. Removing
only unwind registration in a second consumer leaves it linkable but causes the
expected native panic failure.

The Linux resolver returns native TLS offsets relative to the thread pointer.
Its lifecycle uses libc scheduling for the image's compiler TLS destructor list,
then retains storage through POSIX key-destructor passes so later Rust cleanup
can use it. This ordering matters: Rust's
[thread cleanup guard](https://raw.githubusercontent.com/rust-lang/rust/master/library/std/src/sys/thread_local/guard/key.rs)
expects its pthread cleanup to follow compiler TLS destructors. An earlier
immediate-free implementation reinitialized storage during cleanup; the final
regression verifies preservation of the original storage and state.

The [Linux verification notes](#evidence-2026-11-07-linux) describe the native
execution and lifecycle regression. Full artifacts were generated under `.work/linux-verify-gjykg6nt/`. Reproduce with:

```sh
python3 scripts/verify_linux.py --purego-root /path/to/purego-v0.11.3
```

The profile is glibc/AArch64 and one combined native runtime image. Static musl,
other TLS models, TLS-template relocations, native IFUNC definitions, preinit/fini
arrays and arbitrary DSO loading/unloading are unsupported. Cross-image
TLS-destructor interleaving is unverified. Another key accessing or resurrecting
TLS after Bao's callback on the final allowed destructor pass is outside the
profile. Explicit main finalization leaves a small NULL-target libc hook record
and copied argv with process lifetime; zero live TLS blocks does not claim zero
process-lifetime native allocations.

## TLS ABI and destructor stress

The independent lower-level C/Rust TLS probe also passed: eight concurrent native
pthreads, initialized and zero-filled storage, 64-byte alignment, isolation,
24 LIFO/reentrant terminators, and nine released blocks. A native caller and a
lookup function that deliberately clobbers caller-saved state verify required
general registers and **all 128 bits of every SIMD register** across the TLV
thunk. Removing q0/q1 restoration is detected at execution. The executable also
passes signing/strict verification/rerun.

The original TLS verification run used `.work/tls-verify-i76gq2w3/`. The probe labels Rust Drop/panic and GPUI integration as separate checks;
the independent suite above and optional integration below establish those.

## Optional historical GPUI integration

The maintained Bazel reproduction command recorded on 2026-11-08 is:

```sh
bazel run //:verify -- -suite gpui -gpui-root /path/to/gpui-go
```

GPUI was the original reproduction, not a required dependency of Bao. The real
archive has already linked and executed through the full translator. This is
additional integration evidence, separate from the independent examples.

- Input archive SHA-256:
  `586e3366ab771326ec79a9847229ceb77baa5fab83a241670c9200eb92265af7`.
- 1,228 archive members; combined-object SHA-256:
  `a2674460c9ef00d049cbb53da13b1726470abfc81fed14c770b5ab8b68da6907`.
- 888 TLVP address relocations lowered; 36 TLS descriptors supported.
- 131,530 local definitions renamed to preserve symbol-table indexed identity;
  5,681 redundant same-address text aliases coalesced.
- 31,914 original FDEs, 13,495 synthesized compact unwind FDEs, 19 initializers,
  794 system imports, 19 imported-data fixups and 24 final native alignments checked.

The headless handshake, open/update/events, pending request cancellation,
close/quit and Sable shutdown/free pass with `GOMAXPROCS=1` and `4`, and after
signing. A second executable adds test-only entrypoints alongside the unmodified
archive to verify caught panics with two drops, eight std threads and TLS
teardown, imported data, pointer addends, 128-byte alignment and initializer ABI.
A no-unwind-registration negative control links and aborts as expected.

The isolated runtime fixture releases all nine TLS blocks. The GPUI headless
process reports remaining image TLS blocks after explicitly finalizing its
calling thread (the latest runs report one or two); process/background TLS is
not claimed to be fully drained.
Main-thread finalization does not synchronize other native threads.

The recorded integration run used `.work/runtime-verify-h5bwloqn/`. The optional
reproduction at the time was `scripts/verify_gpui.py`; it uses Bao's maintained headless
consumer and public GPUI Go packages, not handoff scratch probe source. GPUI
files were read-only and the input archive hash was unchanged after testing.
No GPL editor code was included.

## Scope and historical failures

The Darwin output uses ELF **input containers containing Darwin ABI code** so
Go preserves alignment; the final signed executable is Mach-O. This does not
establish Linux ABI support. There is no custom Go patch, panic=abort workaround,
code-page patch, runtime extraction or in-memory application loader. Native
helper objects are original Bao sources with checked provenance hashes.

The original TLVP failure and subsequent incomplete stages are retained in
[initial archive translator investigation](#evidence-2026-11-07).
Their failures are historical and have not been relabeled as successful runs.
Known unsupported inputs and platform boundaries are documented in
[README.md](README.md). No Git repository was initialized, and no changes were
committed, pushed or published.

## Detailed verification records

These notes were consolidated from the former evidence directories. Generated
raw artifacts have been removed; verification outcomes and findings retain
their recorded historical context. Current workflows are documented in
[README.md](README.md).

<a id="evidence-2026-11-08-ppc64le"></a>

### 2026-11-08 — PowerPC64LE ELFv2 and TLS register preservation

Verification record: `2026-11-08-ppc64le` (raw artifacts removed).

The maintained Bazel verifier passed for `linux/ppc64le` using the independent
Rust std library in `examples/linux_runtime`. This is actual QEMU 10.0.13 guest
execution on a Linux ARM64 Docker host. Physical PowerPC hardware remains
unverified. ELFv1 and function descriptors are outside this profile.

The producer used Rust 1.99.1, target GNU ld and a glibc sysroot. The consumer
used stock Go 1.26.5, checksum-verified downloaded purego v0.11.3,
`CGO_ENABLED=0`, disabled native compiler paths, and disabled module networking.
No native application shared library, runtime extraction, JIT mapping or
patched Go toolchain was introduced.

Both `GOMAXPROCS=1` and `4` passed: a caught Rust panic with two RAII drops,
eight Rust threads, initialized/zero/128-byte-aligned TLS, nine TLS destructors,
late pthread cleanup retaining the original TLS address and dropped/modified
state, constructors with argc/argv/environ, imported libc data, a native pointer
addend, 128-byte static alignment, allocation and libc qsort calling Rust.
Explicit main-thread finalization left zero live TLS blocks and nine freed.

All 3,342 retained native sections met their ELF alignment, and no PT_LOAD
segment was writable and executable. A separate consumer with the same native
bytes but no FDE registration still linked and then aborted when the Rust panic
executed. Native helper regeneration reproduced the embedded cross blobs byte
for byte.

An independent assembly caller seeded unique 128-bit patterns in every one of
the 64 VSX registers, called the TLS resolver, and compared both halves of every
register. It also checked ordinary TLS-call R2 preservation and an indirect
global-entry call with R2 deliberately set to `0x1357`. All passed. The authored
TLS thunk preserves full VSX state plus FPSCR, VSCR, VRSAVE, CR, XER and the
incoming R2 across both ELFv2 entry paths.

A separate helper copy simulated a C-conforming volatile VSR0 clobber at the
native lookup's return checkpoint. The complete runtime and register probe
still passed. Removing only its VSR0 restoration in another copy preserved
linking and made the probe reject the result. The
[initial integer-only run](#evidence-2026-11-08-ppc64le-integer-initial) is
superseded by this run.

The translation uses 12 TLS descriptors (including the ABI probe) and 484 native relative-data fixups.
The GD/LD resolver, local-dynamic TLS offsets, ELFv2 TOC and local-entry metadata
retain their ABI roles. Relative unwind data fields initialize in writable
native metadata before FDE registration; code pages are never patched at
runtime. Full ignored artifacts are in `.work/verify-linux-cross-4202748795/`.
The run recorded source/executable hashes and the tool/image identity. Common single-image/glibc/TLS lifecycle boundaries are documented in
`examples/linux_runtime/README.md` and `testdata/toolchains/README.md`.

```sh
.work/tools/bazel --output_user_root="$PWD/.work/bazel-root" run //:verify -- \
  -suite linux-cross -target linux/ppc64le \
  -image bao-cross-investigation:20261108 \
  -evidence .work/linux-ppc64le-new
```

<a id="evidence-2026-11-08-loong64"></a>

### 2026-11-08 — LoongArch64 ELF verification

Verification record: `2026-11-08-loong64` (raw artifacts removed).

The maintained Bazel verifier passed for `linux/loong64` with the standalone
dependency-free Rust std library in `examples/linux_runtime`. This is actual
QEMU 10.0.13 guest execution on a Linux ARM64 Docker host. Physical LoongArch
hardware remains unverified.

The producer built a Rust 1.99.1 static archive and ran `bao build` with the
target GNU linker and glibc sysroot. The consumer used stock Go 1.26.5,
checksum-verified downloaded purego v0.11.3, `CGO_ENABLED=0`, disabled native
compiler paths, and disabled module networking. No native application dylib,
runtime extraction, JIT mapping or custom Go linker was used.

Both `GOMAXPROCS=1` and `4` passed: a Rust panic caught with two RAII drops;
eight Rust threads; initialized, zero, and 128-byte-aligned TLS; nine TLS
destructors; original TLS address/state retained during later pthread cleanup;
constructor order/argc/argv/environ; imported libc data; an interior pointer;
128-byte static alignment; allocation; and a Rust callback called by libc qsort.
Explicit main TLS finalization left zero live blocks and nine freed blocks.

All 6,581 retained native sections met their actual ELF alignment, and no
PT_LOAD segment was both writable and executable. Removing only native FDE
registration in a separate consumer preserved linking and made the Rust panic
abort, confirming that the registered unwind data was necessary.

The translation uses 11 TLS descriptors and 6,716 native relative-data fixups.
Those writable metadata fields initialize before unwind registration; runtime
executable pages are never patched. Checked LoongArch CALL36 pairs become B26
plus a retained NOP slot to avoid the pinned Go linker's signed backward-call
encoding bug. LSDA ULEB differences are folded only within one section. Native
helper regeneration through the maintained Go tool reproduced both cross
helper blobs byte for byte.

Full ignored artifacts are in `.work/verify-linux-cross-1122680899/`. The result
records source, executable, tool and Docker image identity. The remaining
single-image/glibc/TLS lifecycle boundaries are documented in
`examples/linux_runtime/README.md` and `testdata/toolchains/README.md`.

```sh
.work/tools/bazel --output_user_root="$PWD/.work/bazel-root" run //:verify -- \
  -suite linux-cross -target linux/loong64 \
  -image bao-cross-investigation:20261108 \
  -evidence .work/linux-loong64-new
```

<a id="evidence-2026-11-08-ppc64le-integer-initial"></a>

### 2026-11-08 — Initial PowerPC64LE verification (integer-only; superseded)

Verification record: `2026-11-08-ppc64le-integer-initial` (raw artifacts removed).

This integer-only run predates the [full VSX/TOC verification](#evidence-2026-11-08-ppc64le). Its original results remain below as historical context.

The maintained Bazel verifier passed for `linux/ppc64le` using the independent
Rust std library in `examples/linux_runtime`. This is actual QEMU 10.0.13 guest
execution on a Linux ARM64 Docker host. Physical PowerPC hardware remains
unverified. ELFv1 and function descriptors are outside this profile.

The producer used Rust 1.99.1, target GNU ld and a glibc sysroot. The consumer
used stock Go 1.26.5, checksum-verified downloaded purego v0.11.3,
`CGO_ENABLED=0`, disabled native compiler paths, and disabled module networking.
No native application shared library, runtime extraction, JIT mapping or
patched Go toolchain was introduced.

Both `GOMAXPROCS=1` and `4` passed: a caught Rust panic with two RAII drops,
eight Rust threads, initialized/zero/128-byte-aligned TLS, nine TLS destructors,
late pthread cleanup retaining the original TLS address and dropped/modified
state, constructors with argc/argv/environ, imported libc data, a native pointer
addend, 128-byte static alignment, allocation and libc qsort calling Rust.
Explicit main-thread finalization left zero live TLS blocks and nine freed.

All 3,340 retained native sections met their ELF alignment, and no PT_LOAD
segment was writable and executable. A separate consumer with the same native
bytes but no FDE registration still linked and then aborted when the Rust panic
executed. Native helper regeneration reproduced the embedded cross blobs byte
for byte.

The translation uses 11 TLS descriptors and 484 native relative-data fixups.
The GD/LD resolver, local-dynamic TLS offsets, ELFv2 TOC and local-entry metadata
retain their ABI roles. Relative unwind data fields initialize in writable
native metadata before FDE registration; code pages are never patched at
runtime. Full ignored artifacts are in `.work/verify-linux-cross-4245801714/`.
The run recorded source/executable hashes and the tool/image identity. Common single-image/glibc/TLS lifecycle boundaries are documented in
`examples/linux_runtime/README.md` and `testdata/toolchains/README.md`.

```sh
.work/tools/bazel --output_user_root="$PWD/.work/bazel-root" run //:verify -- \
  -suite linux-cross -target linux/ppc64le \
  -image bao-cross-investigation:20261108 \
  -evidence .work/linux-ppc64le-new
```

<a id="evidence-2026-11-07-linux"></a>

### 2026-11-07 — Native Linux arm64 ELF verification

Verification record: `2026-11-07-linux` (raw artifacts removed).

`scripts/verify_linux.py` passed with the standalone dependency-free Rust
library in `examples/linux_runtime`. No GPUI source, archive or Go module was
used. Target execution ran on the existing native Linux/aarch64 Docker daemon,
using the pinned official Rust 1.99.1 Debian 12 image.
The Go consumer was cross-built by stock Go 1.26.5 with `CGO_ENABLED=0` and
deliberately invalid `CC`, `CXX` and `RUSTC`, with module networking disabled.

Both `GOMAXPROCS=1` and `4` runs passed. The ELF executable caught a Rust panic
with two RAII drops, joined eight Rust threads, verified their native TLS
destructors and isolated initialized/zero/128-byte-aligned TLS, then finalized
the locked main thread. All nine native TLS blocks were freed, with zero live.
An independent pthread key verified that cleanup after compiler TLS destructors
still observes the original native TLS address and its dropped/modified state.

Five native initializers ran in numeric priority order, with native copies of
argc/argv and libc environ; `std::env::args_os` worked. Native libc allocation,
an imported data pointer, an interior pointer addend, a Rust callback invoked by
libc qsort, and 128-byte static alignment passed. All 6,693 retained native
section addresses were checked against their actual ELF `sh_addralign` values;
the executable had no writable/executable PT_LOAD segment.

The sensitivity control used identical native objects with only DWARF
registration calls removed from a separate Go consumer. It still linked and
aborted when the Rust panic executed. Successful
cross-linking alone is therefore not treated as a runtime pass.

Source/input and artifact hashes, tool versions and target image digest were
recorded during the run. Full ignored artifacts, including both executables
and generated packages, were generated under `.work/linux-verify-gjykg6nt/`.
The earlier iteration `.work/linux-verify-j_emexpp/` exposed incorrect immediate
TLS storage reclamation: later Rust pthread cleanup reinitialized TLS and freed
17 blocks. That result is superseded by the lifecycle fix and the explicit late
cleanup regression in this successful run.

Scope is Linux AArch64/glibc, one translated runtime image, normal Go internal
linking, and the checked TLSDESC instruction form. Static musl, other TLS models,
native preinit/fini arrays, input IFUNC definitions, relocations in TLS templates,
arbitrary DSO loading/unloading, cross-image TLS destructor interleaving and
another pthread key resurrecting/accessing TLS after Bao's final allowed
destructor-pass callback remain unsupported or unverified. Main explicit
finalization leaves a small NULL-target libc hook record and copied argv with
process lifetime, because Go exit skips queued libc TLS-exit callbacks.

Reproduce from Bao:

```sh
python3 scripts/verify_linux.py --purego-root /path/to/purego-v0.11.3
```

<a id="evidence-2026-11-07"></a>

### 2026-11-07 — Initial archive translator investigation

Verification record: `2026-11-07` (raw artifacts removed).

This records the initial incomplete implementation and failures, superseded by the later successful verification entries above. Claims of unsupported behavior below describe that initial stage.

The translator is a working partial implementation; **full GPUI linkage and
execution remain unsupported**. This document separates transformed objects,
successful Go links and executed native behavior. No GPUI file was modified.
The Bao workspace initially contained no files or Git repository; no repository
was initialized and nothing was committed or published.

#### Inputs and tools

- Host: macOS/arm64.
- Go: `go version go1.26.5 darwin/arm64`.
- Rust: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- SDK: macOS 26.5, discovered with `xcrun --show-sdk-version`.
- Archive: `/Users/moriyoshi/Source/gpui-go/target/release/libgpui_go_native.a`.
- Archive SHA-256:
  `586e3366ab771326ec79a9847229ceb77baa5fab83a241670c9200eb92265af7`.
- Combined object's SHA-256:
  `a2674460c9ef00d049cbb53da13b1726470abfc81fed14c770b5ab8b68da6907`.
- Headless consumer source:
  `/Users/moriyoshi/Source/gpui-go/.agents-workspace/tmp/static-nocgo-gpui-probe`.
- Local purego v0.11.3 source:
  `/Users/moriyoshi/Source/gwigwi/build/go-mod/github.com/ebitengine/purego@v0.11.3`.

The pure-Go archive reader inspected all 1,228 object members. Archive-wide
definition resolution leaves 797 unresolved symbols, including system functions,
framework functions/data and section-boundary pseudo-symbols. These are not
797 observed link errors: the linker stops after a limited number of diagnostics.
Weak symbols and other conservative rejections are reported separately.

#### Results

| Check | Result | What it establishes |
| --- | --- | --- |
| `CGO_ENABLED=0 go test ./...` | PASS | BSD/GNU archive parsing; simple-object acceptance; semantic rejection; symbol resolution; function density; checked TLVP rewriting and negative controls |
| `CGO_ENABLED=0 go vet ./...` | PASS | Maintained Go code passes vet |
| Rust leaf archive -> `bao pack` | PASS | Pure-Go packaging and generated address accessor |
| Packaged leaf -> Go link with cgo disabled | PASS | Supported native bytes link into executable |
| Leaf executes 20 + 22 | PASS, 42 | ABI-aware foreign call via purego |
| Ad hoc Hardened Runtime sign + strict signature verify + rerun | PASS, 42 | The leaf remains executable after signing |
| Actual compiler TLS, constructor, catch_unwind object fixtures | Correctly rejected | These required semantics are not silently discarded |
| Minimal lowered TLS plus public dynamic import | Link FAIL | Bootstrap pointer relocation is another independent linker boundary |
| Unmodified real archive combined object -> Go link | FAIL, TLVP | Reproduces the handoff failure |
| Real combined object -> checked TLVP lowering | PASS, 888 relocations | All observed TLVP address relocations are expressible as supported GOT address relocations |
| Lowered real object -> Go link | FAIL | TLS bootstrap, section boundaries, framework data, function density remain |
| `CGO_ENABLED=0` with external link mode | FAIL as expected | Stock Go rejects this alternative configuration |
| Full headless GPUI protocol, TLS, panic unwind, Sable teardown | NOT RUN | No linkable executable exists |
| Native AppKit/UI/input; Linux/ELF; notarization; ordinary go-get packaging | NOT VERIFIED | Outside the established result |

The initial results are summarized in the table above.
The complete last run, including binaries, before/after reports and the copied
read-only consumer, is under `.work/verify-epqejt5v/` (ignored scratch).
No log claiming a shared-library execution pass was produced by running GPUI:
the inherited headless probe never linked and was never executed here.

#### The TLVP translation

`LowerTLVP` in `internal/translate/translate.go` changes only the relocation
type nibbles:

```text
ARM64_RELOC_TLVP_LOAD_PAGE21    (8, PC relative) -> GOT_LOAD_PAGE21    (5)
ARM64_RELOC_TLVP_LOAD_PAGEOFF12 (9)              -> GOT_LOAD_PAGEOFF12 (6)
```

It requires a local descriptor in an S_THREAD_LOCAL_VARIABLES section, the
expected ADRP or 64-bit LDR instruction, valid bounds, external symbol addressing,
4-byte relocation width and the expected PC-relative bit. Unknown variants and
undefined descriptor targets are rejected. The original input is not mutated.

Go's ARM64 linker relaxes GOT loads of locally defined symbols into address
calculations (ADRP/LDR becomes ADRP/ADD). This supplies the address of the same
TLV descriptor; its resolver call remains in the native code. It does not turn
thread-local data into global data or implement the resolver. The unit test
compares every byte of the output against an independently constructed expected
file, including all TLS descriptor bytes. Wrong instruction, target and
PC-relative variants are negative controls.

The combined archive contains 444 PAGE21 and 444 PAGEOFF12 TLVP relocations.
After translation, neither type remains, and the original 2065/2066 diagnostics
disappear. The command still labels its output **INCOMPLETE** and emits a
before/after report with `packable: false`.

#### Remaining observed boundaries

The combined object has 36 TLS descriptors (`__thread_vars`, 0x360 bytes),
initialized and zero-fill thread templates, 19 initializer pointers,
`__eh_frame`, `__compact_unwind`, stronger alignments, weak definitions and native
startup text outside `__text`. Merely preserving their source bytes does not
preserve their executable-image semantics through the stock Go object reader.

The lowered real link reports, among others:

```text
main(__DATA/__thread_vars): relocation target _tlv_bootstrap not defined
too many functions in a findfunc bucket! 1106/4024 10 260
main(__DATA/__const): relocation target section$end$__DATA$_CTOR0_ISIZE_FN not defined
main(__DATA/__const): relocation target section$start$__DATA$_CTOR0_ISIZE_FN not defined
main(__DATA/__const): relocation target kCTFontPostScriptCIDNameKey not defined
```

The lowered-link diagnostics above were recorded during that initial run.
The inspector finds a maximum of 265 native symbols in a sliding 4 KiB window.
This is a conservative density warning; the actual Go link supplies the evidence
that its findfunc subbucket limit is hit for this placement. Removing source
symbols or code was not used to conceal that failure.

A separate tiny C TLS object isolates imports from the large archive. Its two
TLVP relocations lower successfully. Declaring this supported public directive:

```go
//go:cgo_import_dynamic _tlv_bootstrap _tlv_bootstrap "/usr/lib/libSystem.B.dylib"
```

changes the link failure to:

```text
main(__DATA/__thread_vars): unexpected reloc for dynamic symbol _tlv_bootstrap
```

The minimal import probe produced the diagnostic above.
The program only takes the native function address; it never executes incomplete
TLS. Even resolving that pointer would not arrange descriptor initialization,
per-thread storage, destructors or dyld's TLS image registration.

Local pinned Go sources substantiate these boundaries:

- `src/cmd/link/internal/loadmacho/ldmacho.go`, section import loop: imports only
  `__TEXT` and `__DATA`, skips `__eh_frame`, and marks only `__TEXT/__text` as
  STEXT. TLS/initializer section types are not assigned their native image roles.
- `src/cmd/link/internal/arm64/asm.go`, Mach-O relocation switch: no TLVP cases;
  UNSIGNED relocations to dynamic symbols produce `unexpected reloc for dynamic
  symbol`; GOT_LOAD supports local address relaxation.
- `src/cmd/link/internal/ld/pcln.go`, `findfunctab`: diagnoses differences >= 256
  before encoding subbucket offsets as uint8.

These sources were read locally, not copied into Bao. No global Go or Rust
installation was changed.

This demonstrates limitations of feeding native Mach-O semantics directly to
the current Go reader. It is not a proof that a sufficiently comprehensive
translator plus native ABI shims could never target stock Go. That larger
translation remains unimplemented, especially TLS/thread exit and Rust unwind
behavior. A linker/toolchain change must be explicit if it turns out necessary.

#### Reproduction

From this workspace:

```sh
mkdir -p .work
GOCACHE="$PWD/.work/go-build" CGO_ENABLED=0 go test ./...
GOCACHE="$PWD/.work/go-build" CGO_ENABLED=0 go vet ./...
python3 scripts/verify_darwin.py \
  --purego-root /Users/moriyoshi/Source/gwigwi/build/go-mod/github.com/ebitengine/purego@v0.11.3 \
  --gpui-root /Users/moriyoshi/Source/gpui-go
```

The script forces fresh package content when replacing `.syso` files and writes
new executable paths. It does not cite a cached executable as evidence. Module
network access is disabled. If the pinned tool versions, archive or the handoff
probe changes, a new result needs review rather than relabeling the old evidence.

The native combination performed by the maintainer script is:

```sh
/usr/bin/ld -r -arch arm64 -platform_version macos 11.0 26.5 \
  -all_load /Users/moriyoshi/Source/gpui-go/target/release/libgpui_go_native.a \
  -o .work/gpui-combined.o
```

This is maintainer preprocessing for the real diagnostic. `bao inspect` and
`bao pack` themselves do not invoke `ld`, `ar`, Rust or C. No runtime extraction,
native-code in-memory loader, source workaround, GPL editor code, commit or
external service was introduced.

## 2026-11-08: Journal naming and append-only protocol

Renamed the root journal to `JOURNAL.md`, updated its README link, and added
`AGENTS.md` with the journaling conventions adapted for Bao. Ordinary work now
appends dated findings, decisions, and verification outcomes at the end. Earlier
consolidated entries retain their existing order and content; corrections and
superseding findings belong in new entries. Raw scratch artifacts stay in
ignored `.work/`, and user workflows remain in `README.md`.

Validation confirmed the uppercase directory entry, preservation of all earlier
journal bytes, and the README and agent-guide journal links. Documentation-only
change; no runtime or build behavior changed.

## 2026-11-08: Bazel CLI release pipeline

Added `.github/workflows/release.yml` for SemVer `v*` tags and manual tag runs.
Pushed tags publish after the gates pass; manual runs default to a dry run and
require `publish=true` to publish. Metadata resolution rejects invalid SemVer,
numeric prerelease identifiers with leading zeros, branch runs, and a checkout
that does not match the tag's commit. The publication job dereferences the remote
tag again, including annotated tags, before creating a complete draft release
and publishing it. Existing releases/drafts are not overwritten. A failed upload
can leave a draft requiring inspection and removal before retrying.

Six Bazel release targets embed the existing Bao library with explicit pure Go
GOOS/GOARCH settings: Darwin arm64/amd64 and Linux amd64/arm64/loong64/ppc64le.
Linux amd64 is a CLI host, not a newly supported native translation target.
Stable workspace status keys stamp the version and full commit through rules_go
`x_defs`, so changing release identity invalidates cached link actions. Ordinary
development binaries keep their development version. The Go SDK remains 1.26.5
and Bazel remains 8.4.2; no native helpers are regenerated in this pipeline.

`release/build.sh` stages all six binaries and invokes the stdlib-only
`cmd/bao-release` packager through Bazel. It checks executable format,
architecture, ELF endianness/type and absence of a dynamic ELF interpreter,
normalizes archive ordering/ownership/modes/timestamps, and emits six tarballs,
release metadata and SHA256SUMS. Each archive carries Bao's Apache license and
the original Go/purego license texts and provenance for embedded bootstrap
templates. Existing output directories are refused. Local integration caught
Bazel run's changed working directory; output paths are now made absolute before
invoking the packager. No Python dependency was introduced.

The workflow pins checkout/upload/download/attest/setup-bazel actions to commits
resolved from their official tags (v6/v6/v7/v4/0.19.0), pins Bazelisk 1.27.0, and
uses the existing Bazel dependency lockfile with `--lockfile_mode=error`.
Only the publication job has contents-write permission and it executes no
checked-out scripts. The build job can issue GitHub/Sigstore attestations when
publication is requested; dry runs omit attestations. GitHub provenance depends
on repository/workflow/runner trust and is separate from Bao's independently
approved native-module signing policy. It is not a publisher trust root.

Release gates cover fresh Bazel tests, packaged CLI version checks, native
Darwin arm64/amd64 framework/TLS/bindings suites, the Darwin arm64 signature and
cache negative controls, native Linux arm64 runtime/bindings, and QEMU Linux
loong64/ppc64le runtime/bindings and CLI execution. On a native Linux arm64 host,
the verifier now copies and records the selected CLI artifact's hash as its
container producer, instead of recompiling a substitute. Other verifier hosts
retain their cross-built arm64 producer behavior. Workflow verification logs
are uploaded as short-lived artifacts; scratch data stays under `.work/`.

Local verification on macOS 26.5.2/arm64, SDK 26.5, Rust 1.99.1:

* `bazel test --lockfile_mode=error --nocache_test_results //:tests`: all eight
  Bazel test targets passed, including release metadata, deterministic archive
  and license preservation, complete checksums, wrong architecture, incomplete
  matrix and overwrite controls. `CGO_ENABLED=0 go test ./...` and `go vet ./...`
  passed with the workspace Go cache.
* `actionlint` 1.7.12 accepted the workflow and `bash -n release/*.sh` passed.
  Isolated Git fixtures under `.work/` passed lightweight/annotated tag
  resolution, invalid SemVer rejection and mismatched HEAD rejection. The root
  workspace remains a source export without Git metadata.
* `BAO_RELEASE_VERSION=v0.1.0-rc.1 BAO_RELEASE_COMMIT=<40 a characters>
  SOURCE_DATE_EPOCH=1770000000 bash release/build.sh .work/release-check-1`
  built and packaged all six hosts. The local Bazel binary and output root were
  supplied with BAZEL/BAO_BAZEL_ROOT. A second build into `release-check-2`
  produced identical SHA256SUMS. All seven entries verified. These are synthetic
  test identities, not actual releases or source-identity assertions.
* Both packaged Darwin CLIs passed version/commit/Go checks, targets and help;
  amd64 ran through Rosetta. Packaged Linux arm64 ran natively in the existing
  arm64 Colima Docker VM. Linux amd64/loong64/ppc64le CLI version checks passed
  under QEMU in `bao-cross-investigation:20261108` (image ID
  `sha256:24a552d0ae99460f8b786bd14a919e251b02d4a4f0c61660fa2db585e2828d3d`).
* Changing the warm-cache build to v0.1.0-rc.2, a 40-character b commit and epoch
  1770000001 produced the new metadata in the executable, rather than the old
  stamp. The packaged Darwin arm64 rc.1 binary passed `bazel run //:verify --
  -bao <extracted-binary> -suite bindings -target darwin/arm64 -evidence
  .work/results/release-bindings-arm64`, including C manifest/DWARF paths,
  optimized Rust std, native debug stripping, signing, scheduler progress,
  unwind negative control and TLS destructor cleanup.

GitHub-hosted execution, OIDC attestation issuance, upload failure recovery,
publication and the native-Linux-host artifact-copy branch have not been run in
this session. Full native suites beyond the Darwin arm64 bindings suite were
not rerun for this packaging change. Physical LoongArch/PowerPC hardware and
Apple Developer ID/notarization remain unverified. Hosted runner SDKs and the
existing pinned Debian cross-package recipe can change or become unavailable;
their failures block publication. README documents operation, dry runs,
verification and these boundaries. No release, remote workflow, commit or push
was performed.

## 2026-11-08: Public Go library packages

Moved the reusable `bindings`, `linuxelf`, `toolchain`, `translate` and `verify`
packages from `internal/` to the module root. External callers can now import
`github.com/moriyoshi/bao/<package>` directly. These are the same implementations
used by the CLI, with their existing types and function names; no forwarding
facade or duplicate implementation was added. The low-level archive parser
remains private in `internal/ar`. Public library Bazel targets have public
visibility, while the archive parser retains repository-local visibility.

Updated Go imports, Bazel dependencies/test targets, native helper regeneration
and TLS probe paths, release license/provenance input paths, and README commands.
README now documents the five library packages with an inference example and
explains the low-level translation and verified-build integration boundaries.
The `verify.Tool` comment explicitly identifies it as Build's subprocess hook,
not a standalone link-only verification entrypoint. Verification policy and
cache behavior are unchanged. Earlier journal paths remain historical records;
this entry supersedes their description of the current package layout.

All 71 moved native sources/objects, bootstrap templates, licenses, compiler
fixtures and provenance files (excluding Go/BUILD/Markdown files) matched the
existing Git index byte-for-byte after relocation. Native helpers were not
regenerated. An index was present in this session; it was neither staged nor
rewritten during this refactor, and unrelated user files were preserved.

Verification on macOS 26.5.2/arm64 with Go 1.26.5, Bazel 8.4.2, SDK 26.5 and
Rust 1.99.1:

* `CGO_ENABLED=0 go test ./...`, `go vet ./...`, and
  `bazel test --lockfile_mode=error --nocache_test_results //:tests` passed.
  All eight Bazel test targets executed successfully under the new labels.
* A separate module named `example.test/bao-client` under
  `.work/public-api-client`, using a local module replacement and disabled
  module networking, imported all five public packages. It executed optimized
  Mach-O/ELF DWARF inference, Darwin inspection, both native debug strippers,
  target detection, key generation, signing and policy authentication. Inference
  on stripped objects and authentication of a changed signature were rejected.
  A separate program importing `github.com/moriyoshi/bao/internal/ar` was rejected
  by Go with `use of internal package ... not allowed`.
* `bazel run //:verify -- -suite bindings -target darwin/arm64 -evidence
  .work/results/public-api-bindings-arm64` passed, including generated C
  manifest/DWARF consumers, optimized Rust std, native unwind negative control,
  native debug stripping, scheduler progress, signing and TLS teardown.
* `bazel run //:verify -- -suite tls -target darwin/arm64 -evidence
  .work/results/public-api-tls-arm64` passed using the relocated native helper
  source paths, including the disabled-SIMD-restoration negative control,
  eight threads, nine freed TLS blocks and signed executable reruns.
* `release/build.sh .work/release-public-api` built and packaged all six CLI
  hosts with synthetic version `v0.1.0-api-check`, a 40-character c commit and
  source epoch 1770000002. All checksum entries passed, the archive contained
  the original license/provenance payloads, and the extracted Darwin arm64 CLI
  passed version/commit, target listing and build-help smoke checks. Actionlint
  still accepted the release workflow.

Linux and Darwin amd64 integration suites and GitHub-hosted publication were not
rerun for this layout change. External Go importability was exercised; Bazel
visibility was configured and the repository targets tested, without claiming
a separate external Bazel workspace run. No release, commit or push was made.

## 2026-11-08: Comparing reusable Go ar parsers

Compared upstream erikgeiser/ar and please-build/ar for a possible replacement
of Bao's small archive parser. Neither was adopted and Bao's module/Bazel
dependencies are unchanged. Read-only upstream checkouts and the comparison
program/results are in ignored `.work/ar-comparison/`; no upstream report,
commit, push or publication was made.

The exact checked HEADs were erikgeiser/ar
`067aafdb81fc5bfefe34bf1e5bde609caae91c7f` (2026-07-18, padding fixes) and
please-build/ar `20fe5956df94b8944a6d16c3988c91494bf3946e` (2025-11-28, BSD
symbol-table name resolution). Neither remote advertised version tags. Both
declare Go 1.19 and MIT licensing, and their production packages use only the
standard library. Erik's module has no dependency requirements; Please's
test suite uses testify 1.11.1 and its transitive test dependencies. Both provide
streaming Next/Read APIs. Erik supports BSD output with optional automatic
member-size determination; Please writes BSD or GNU archives, with GNU long
names registered through its string-table API. These extra writer features
are not needed by Bao's current read-only parser.

On macOS 26.5.2/arm64 with CGO_ENABLED=0 and Go 1.26.5, both upstream
`go test ./...` suites passed. Please's tests initially required downloading
their declared test dependencies into the workspace module cache. The isolated
comparison module uses local replacements for both checkouts and Bao, so its
runtime comparisons run with module networking disabled:

```sh
CGO_ENABLED=0 GOCACHE="$PWD/.work/go-build" GOPROXY=off GOSUMDB=off \
  GOTOOLCHAIN=local GOWORK=off go -C .work/ar-comparison run .
```

The differential program uses Bao's existing parser as its reference for
11 valid synthetic archives and 12 malformed/unsupported inputs. It also
compares member names, order, sizes and payload SHA-256 values on four real
archives: the independent Darwin Rust runtime staticlib (393 members), native
Linux Rust runtime staticlib (426), a Linux cross runtime staticlib (326), and
a freshly compiled Go package archive (2). All four real archives matched with
both libraries after discarding conventional symbol-table records. Both also
preserved duplicate member names and handled Go NUL padding and GNU/BSD long
names in the ordinary cases.

Erik exposes symbol-table records as ordinary members (the GNU `/` record's
name becomes empty); Please automatically skips GNU `/` and three common BSD
symbol-table variants. The comparison adapter removes remaining known symbol
table names from both outputs, including `/SYM64/` and BSD sorted-64 variants.
That filtering is necessary to make the real-archive result comparable to Bao;
it is not a claim of identical behavior without an adapter.

Reproduced differences at those pinned revisions:

* Erik misaligns the next header after a BSD `#1/3` name (`a.o`) with a two-byte
  body. It computes padding after subtracting the name length, rather than
  from the original stored member size. Please reads the same two-member
  archive correctly. Padded even-length LLVM-style names work in both.
* Erik accepts a truncated four-byte member with only two body bytes through
  the conventional Next/io.ReadAll loop; Please returns unexpected EOF. A
  caller checking bytes read against Header.Size can detect this separately.
* Please accepts a header whose 60-byte trailer is `xx` instead of backtick/LF,
  and interprets nonnumeric size text `abc` as zero. Its reader ignores numeric
  parsing errors and does not validate that trailer. Erik rejects both.
* A size of -1 panics during Read in both libraries. A BSD name longer than its
  declared member size also panics in Erik in the tested input. A GNU name
  reference of /-1 and an empty GNU name-table entry panic in Please; Erik
  accepts these latter inputs instead of rejecting the malformed names.
* Both accept a missing final odd-byte pad through the conventional iteration
  loop (EOF while skipping it) and silently discard an invalid pad byte.
* Please rejects GNU `/SYM64/` symbol-table input and member names containing
  slashes. Bao treats names solely as metadata, so its `../escape.o` fixture is
  intentionally valid without extracting files. Erik can retain these names;
  its symbol-table records still require caller filtering.

The comparison favors Erik as a smaller dependency and a potential base for
upstream fixes, with stricter numeric/header parsing than Please. Neither is a
drop-in replacement for Bao's verifier as checked: Erik needs at least the BSD
padding and malformed-size/body handling corrected, plus an explicit adapter
for symbol records and Bao's strict framing. These are deterministic local
reproductions, not a fuzzing campaign, performance benchmark, exhaustive audit,
or a claim about later upstream revisions. Keep the current implementation
until a selected replacement passes the existing archive and signature-input
negative controls.

## 2026-11-08: Reusable archive parsing building block

Following the user's clarification, made Bao's own archive parser a reusable
public package at `github.com/moriyoshi/bao/ar`, rather than importing or copying
an upstream implementation. This supersedes the earlier proposed direction of
waiting for or vendoring erikgeiser/ar. The package is part of Bao's existing
module and Apache-2.0 licensing; no new Go dependency or separate repository was
introduced.

The generic API is `Parse([]byte) ([]Member, error)`. It preserves every member
in archive order and distinguishes regular entries, symbol tables and GNU name
tables with `Kind`. It resolves BSD/GNU extended filenames, preserves duplicate
names, exposes each header's byte offset, and returns capacity-limited payload
slices borrowing the original archive. GNU names share an immutable copy of
the filename table rather than copying a long name for every repeated reference.
`ParseError` carries an offset and wraps format, thin-archive or unexpected-EOF
errors for errors.Is/errors.As. No partial result is returned on failure.

The package remains a read-only structural parser. It does not extract files,
open member paths, invoke native tools, decode ownership/mode/timestamp fields
or interpret symbol-index payloads. Thin archives are explicitly rejected.
Stored member lengths, header trailers, BSD name lengths, GNU name references,
name emptiness/NULs, duplicate GNU name tables and final LF/NUL padding are
checked. Padding uses the original stored length before removing a BSD name
prefix. GNU references remain bounded byte offsets, including suffix references.
README and an executable Go example document ownership, supported formats,
errors and the difference between structural parsing and authentication.

`internal/ar` is now a small object-member adapter over the public package. It
filters bookkeeping records by Kind and preserves ordinary member ordering and
duplicates, including Go's __.PKGDEF. Existing translator, DWARF inference,
target detection and signature-verification callers use this adapter, keeping
their selection policy separate from the general parser. Both public and
adapter tests run in the root Bazel test suite.

The external Bazel consumer exposed a pre-existing reuse blocker: rules_go
rejects an explicitly named SDK in a non-root module. Removed Bao's SDK name
while retaining Go 1.26.5, and changed the verifier's data dependency to
`@rules_go//go`. The verifier locates that runner through its own runfiles,
queries its SDK root, then uses and hashes the actual SDK Go executable for
consumer builds. An initial check without the runner's runfiles failed; the
explicit runfiles environment fixed it. SDK declarations now work both when
Bao is the root workspace and when it is an external dependency. No pinned
tool version changed, and release builds continue using lockfile error mode.

Verification on macOS 26.5.2/arm64, Go 1.26.5 and Bazel 8.4.2:

* `CGO_ENABLED=0 go test ./...` and `go vet ./...` passed. The final
  `bazel test --lockfile_mode=error --nocache_test_results //:tests` executed and
  passed all nine targets. New tests cover all bookkeeping variants, odd/even
  BSD name-prefix padding, GNU suffix references, duplicate names, borrowing and
  append boundaries, stable resolved names, typed error locations and no partial
  results. They retain the malformed-input reproductions from the comparison.
* `go test ./ar -run='^$' -fuzz=FuzzParse -fuzztime=10s -parallel=4` on the final
  parser completed 2,290,417 executions without failure. Earlier development
  fuzz runs also passed; this is bounded fuzzing, not an exhaustive audit.
* `.work/ar-client` is an independent `example.test/ar-client` Go module. Its
  offline client passed using only the public parser, retaining symbol/name
  records and duplicate filenames, checking borrowed payloads and typed errors.
  `go list -deps` showed no other Bao package. The same program built and ran
  from a separate Bazel module using `@bao//ar` and a local Bao override, then
  passed again with the external workspace's lockfile error mode enabled.
* Reused the isolated differential harness against four existing real Rust/Go
  archives. Bao's adapter still produced the same member names, ordering,
  lengths and payload hashes as both comparison libraries after their symbol
  filtering (393, 426, 326 and 2 ordinary members respectively).
* `bazel run --lockfile_mode=error //:verify -- -suite signatures -evidence
  .work/results/public-ar-sdk-signatures` passed after SDK/runfiles resolution.
  It authenticated complete generated modules and actual Go linker archives,
  checked repeated requests and warm-cache/substituted-native-input negatives,
  and built/ran the approved dynamic and static-binding consumers. The fixture
  used local test keys and establishes no publisher authority.
* All six CLI hosts built and packaged with the corrected SDK registration and
  synthetic `v0.1.0-ar-check`/40-character d commit metadata. Checksums and the
  extracted Darwin arm64 version/targets/help smoke checks passed. Actionlint
  continued accepting the release workflow. Final build scratch output is in
  `.work/release-ar-final`; investigation clients and logs stay under `.work/`.

Native helper bytes/licenses were not regenerated or changed. Linux execution,
full framework suites, other SDKs and GitHub-hosted publication were not rerun
for this parser work. No upstream submission, release, Git commit or push was
performed.

## 2026-11-08: v0.0.0 release rehearsal and current Actions pins

The release-readiness review found an initial-rehearsal gap: any v-tag push
would publish after its gates, while manual dry runs skipped provenance. The
user selected v0.0.0 as the test tag and confirmed moriyoshi/bao as the intended
repository. Updated the workflow so a v0.0.0 push runs all build, verification
and attestation steps but skips release publication. An explicit manual run
with publish=true can publish v0.0.0 as a prerelease with --latest=false. Other
v-tags retain automatic publication after successful gates. Manual dry runs
now generate provenance as well, exercising the OIDC capability before release
publication. README describes this behavior and uses v0.0.0 for rehearsals.

Release metadata classifies v0.0.0 as a prerelease even though the tag has no
SemVer prerelease suffix. Added maintained Git-fixture tests for that exception,
stable and prerelease versions, annotated tags, invalid tags and a checkout
that differs from the tagged commit. Tests create temporary fixture commits;
no project commit was made. The fixture script is declared as Bazel test data.

While work was in progress, workflow runner labels were edited to Ubuntu 26.04
for metadata/publication and Ubuntu 26.04 arm64 for Linux verification. These
edits were preserved; the build job remains Ubuntu 24.04. GitHub's current
hosted-runner reference lists the new labels. Actionlint 1.7.12's built-in label
list predates them, so .github/actionlint.yaml filters only the exact unknown
label diagnostic for ubuntu-26.04 and ubuntu-26.04-arm. Other lint checks remain
active. No runner was declared to be self-hosted.

At the user's request, queried each action's official latest-release API and
resolved its release tag to a commit, dereferencing annotated tags. The current
workflow uses these exact released versions as checked on 2026-11-08:

* actions/checkout v7.0.1: 3d3c42e5aac5ba805825da76410c181273ba90b1
* actions/upload-artifact v7.0.2: cf430e030ddbb5b0abf93d22962f4752f3646cd9
* actions/download-artifact v8.0.2: 9000827ccba6bdab643e8b6fd33ac0654aef8333
* bazel-contrib/setup-bazel 0.19.1: 104e3eea9447cdaa4b00d0fb46191a3985d26ab3
* actions/attest v4.2.2: 1e69f48acb82d1966a394da916b4c1698aa569d6

All are still pinned to immutable commits with exact version comments. Attest's
existing commit was already the latest release's commit. Reviewed the action
metadata: these releases use Node 24, the configured inputs remain supported,
upload's archive default remains true, download's skip-decompress default is
false and its digest-mismatch default is error. No compiler/SDK version changed.
The action updates have been statically checked, not executed on GitHub yet.

Local verification on macOS 26.5.2/arm64 with Bazel 8.4.2 and Go 1.26.5:

* All nine Bazel targets passed with lockfile error mode and fresh test execution,
  including the new release metadata tests. CGO_ENABLED=0 go test ./... and
  go vet ./... passed. Actionlint, bash -n release/*.sh and git diff --check
  passed on the updated workflow/scripts.
* release/build.sh .work/release-v0.0.0 built six CLI archives stamped v0.0.0,
  a deliberately synthetic all-zero 40-character commit and epoch 1770000004.
  There was no project HEAD to stamp. All seven checksum entries passed. These
  artifacts test packaging and are not publishable source-identity evidence.
* Both Darwin CLI archives passed version/commit, targets and build-help checks;
  amd64 ran under Rosetta. The packaged Linux arm64 CLI passed in the existing
  native arm64 Docker VM. Linux amd64, loong64 and ppc64le version checks passed
  under QEMU in the existing cross-investigation image. No hosted native suites
  or real OIDC issuance were run by this local rehearsal.

Repository state changed externally during this work: initially no remote or
HEAD existed and the GitHub API returned 404 for the planned repository. The
public moriyoshi/bao repository and origin SSH remote were subsequently present,
and the initial source tree had been staged. It still had no project commit.
The active gh account was a different work profile. Verified the existing
personal moriyoshi profile through an ignored helper that captures its stored
credential in subprocess memory, uses it only for gh and never prints it;
global authentication settings were not switched. Read-only API calls confirmed
the personal account and public repository. No credentials were written to
source or logs. Hosted rehearsal still requires the initial project commit and
push; actual release publication remains unperformed.

## 2026-11-08: README status and documentation badges

Added GitHub Actions and pkg.go.dev badges below the README title. The Actions
badge links to the existing release workflow, which contains the CI gates; the
Go Reference badge links to the module's documentation page. The existing image
and introduction remain intact. Verified repository/module/workflow paths and
Markdown diff whitespace. Badge status depends on hosted workflow execution and
pkg.go.dev indexing; neither was triggered by this documentation edit.

## 2026-11-08: Consumer-focused CLI release documentation

Reduced README's CLI releases section to download locations, available hosts,
checksum/provenance verification, extraction, and relevant trust boundaries.
Removed maintainer instructions for rehearsals, publication, local packaging,
and CI gates. This supersedes the README coverage described in the earlier
release pipeline and v0.0.0 rehearsal entries; release behavior is unchanged.
Corrected the signature-verification section link and added --ignore-missing
so checksum verification supports downloading only the chosen host archive.

Verification on Darwin arm64: reviewed git diff -- README.md JOURNAL.md and ran
git diff --check -- README.md JOURNAL.md successfully. Compared platform/archive
names and the provenance bundle path with release/build.sh,
cmd/bao-release/main.go, and .github/workflows/release.yml. shasum --help
(shasum 6.02) confirms --ignore-missing support. Documentation-only change;
no builds, runtime tests, downloads, or hosted workflows were run.

## 2026-11-08: README consumer and developer instructions

Reorganized README into two audience sections. Consumer instructions cover using
Bao's CLI and public Go libraries, producing native Go packages, calling them
from applications, supported boundaries, and signature verification. Developer
instructions cover building Bao itself, translation internals, test and
integration suites, and native-helper regeneration. Licensing remains shared.
Application call/build examples and startup-thread TLS finalization now appear
in a dedicated generated-package usage section. Producer examples use the
released `bao` executable; Bazel source-build commands remain in the developer
section. Existing section fragments are preserved, with explicit aliases for
renamed headings. This continues the preceding consumer-focused CLI release
documentation change without restoring the removed release-maintenance content.

Verification on Darwin arm64 with Python 3.14.6:
`python3 .work/readme-audience-split/check.py` passed. It checked all 25 original
heading/explicit anchors, local README link targets, balanced code fences, and
preservation of all 20 original code examples after normalizing producer CLI
invocations. It also checked that source-build, verifier and helper-regeneration
commands are outside the consumer section and that the prior journal bytes
remain an unchanged prefix. `git diff --check -- README.md JOURNAL.md` passed.
Scratch snapshots and the checker remain under ignored `.work/`. This was a
documentation-only reorganization; no compilation, linkage, runtime execution,
signing checks, downloads, or hosted workflows were performed.

## 2026-11-08: Go 1.26.10 and the first hosted release rehearsal

Raised the downloaded Bazel SDK, go.mod toolchain directive, CLI doctor/version,
translation/link verification profiles, release metadata/smokes and maintained
documentation to Go 1.26.10. The minimum go directive remains 1.26.0. Existing
native helpers, generated binding templates and their licensing were preserved.
The LoongArch B26 lowering remains necessary: the new stock linker's CALL36
high-immediate sign extension still has the previously documented limitation.

Local verification used Bazel 8.4.2, Go 1.26.10, Rust 1.99.1, macOS 26.5.2/arm64
and SDK 26.5. All nine Bazel targets passed with --lockfile_mode=error and
--nocache_test_results. The maintained ci/check.sh unit entry point also passed
build/version consistency and SDK go vet ./... checks. Framework examples, TLS
register/destructor controls, scalar manifest/DWARF bindings, native debug
stripping and Rust panic/thread cleanup passed for Darwin arm64 natively and
Darwin amd64 under Rosetta. No Go 1.26.10 native Intel hosted execution is claimed.
Linux runtime and binding suites passed on native arm64 Docker, with loong64
and ppc64le executed under QEMU 10.0.13 in the maintained cross image. These
included unwind and PowerPC register/TOC negative controls, not just linkage.
Compact results are under .work/results/go12610-{darwin,linux}-*.

Reproduction uses bazel run //:verify -- -suite darwin|tls|bindings -target
darwin/arm64 or darwin/amd64; Linux uses -suite linux, -suite linux-cross
-target linux/loong64|linux/ppc64le -image bao-cross-investigation:20261108,
and -suite bindings with each corresponding target/image. Separate invocations
are required for each suite and target. The Docker cross recipe pins its base,
compilers, sysroots and QEMU in testdata/toolchains/linux-cross.Dockerfile.

release/build.sh .work/release-go12610 built all six CLI host archives with
BAO_RELEASE_VERSION=v0.0.0, an intentionally all-zero 40-character commit and
SOURCE_DATE_EPOCH=1794110194. All seven checksum entries passed. Packaged CLI
version/targets/help checks passed on native Darwin arm64, Rosetta Darwin amd64,
native Linux arm64 Docker and QEMU Linux amd64/loong64/ppc64le. Logs are under
.work/release-go12610-smoke and .work/results/go12610-release-smoke. The zero
commit explicitly makes these local packaging tests, not publishable evidence.

Read the completed public workflow supplied by the user:
https://github.com/moriyoshi/bao/actions/runs/42444863890. Its source was commit
62d239cddb0348c5ecca9ef0e79f36483e2e2829, tag v0.0.0, using Go 1.26.5. Metadata,
unit/build/package, native macOS arm64 and Intel amd64, Linux arm64 and QEMU
LoongArch/PowerPC gates all succeeded, including actual GitHub OIDC attestation.
Publication was skipped as designed for this rehearsal. Downloaded release-assets
to .work/hosted-run-42444863890; all seven SHA256SUMS entries passed. Also passed:

    gh attestation verify bao_v0.0.0_darwin_arm64.tar.gz --repo moriyoshi/bao \
      --signer-workflow moriyoshi/bao/.github/workflows/release.yml \
      --source-ref refs/tags/v0.0.0 --bundle provenance.sigstore.json

This supersedes earlier statements that hosted execution/OIDC and native Intel
execution had not occurred, for that exact old-toolchain source only. It does
not test the pending SDK, CI, scanning or Bazel backend changes. No project
commit, push, workflow dispatch or release publication was performed here.

## 2026-11-08: Independent CI with content-addressed success records

Added .github/workflows/ci.yml for branch pushes, pull requests, manual runs and
reuse by the release workflow. Four suites cover unit checks, both macOS
architectures, and native Linux arm64 plus QEMU loong64/ppc64le. ci/check.sh owns
the entry points; macOS arm64 also runs signature/source-scan and independent
Bazel consumer controls. Release publication requires this CI job in addition
to the existing fresh packaged-binary verification gates.

ci/cache.sh addresses a successful suite by a SHA-256 descriptor containing the
Git tree ID, suite, ImageOS, ImageVersion, RUNNER_OS and RUNNER_ARCH. Tracked
source, native blobs, toolchain pins, workflows and docs all affect the tree;
commit messages/timestamps/tag names do not. Unknown runner identity disables
reuse. A dirty tracked tree is refused before fingerprinting, recording or
validation. Exact-key restoration has no prefix fallback; success is recorded
only after every command passes, with the original run URL and source commit.
Restored metadata is parsed as bounded data, never executed. Cache hits report
the original passing run rather than claiming fresh native execution.

Pull requests do not restore/save success records. Only default-branch/tag runs
save them; manual force=true bypasses reuse. This assumes trusted GitHub cache
and workflow permissions, not an independent signing authority or proof that
external services stayed unchanged. Cache keys are immutable; force runs fresh
checks and uploads their results without replacing an existing cached record.
The latest actions/cache restore/save v6.1.0 is pinned to
55cc8345863c7cc4c66a329aec7e433d2d1c52a9, alongside the earlier current action pins.

Meaningful cmd/bao-release CI tests create temporary Git fixture commits and
show that identical trees across commits retain their key, changed source/suite/
runner images invalidate it, dirty inputs cannot record a pass, and missing,
partial, corrupt or foreign-run records fail validation. ci/check.sh unit passed
locally with the pinned SDK and fresh nine-target execution. Actionlint 1.7.12
and bash -n ci/*.sh release/*.sh passed. The narrow Ubuntu 26.04 runner-label
ignore now applies to both workflows. Actual new hosted CI/cache reuse remains
unperformed; the successful initial release run predates this workflow.

## 2026-11-08: Offline current-dependency scanning

Added bao verify and public verify.Scan. The user selected current module
dependencies as the default scope. Using the trusted stock Go 1.26.10 resolver,
Bao lists the module build list offline, runs go mod verify, scans downloaded
trees and authenticates complete modules against independently approved
envelopes. All .syso files in those trees count, including unused packages and
other targets. Unsigned native dependencies fail; ordinary nonnative modules
need no Bao policy. Main-module sources and unrelated global cache entries are
excluded. Local replacements are scanned but not covered by Go's cache check.
Undownloaded sources are reported explicitly; an approved missing module fails.
Missing module metadata can prevent offline resolution. No fetching, compiling,
consumer initialization or native execution occurs in this command.

Example: bao verify -C ./consumer -go /trusted/go1.26.10/bin/go -json. For native
dependencies, supply -policy POLICY and repeatable -manifest ENVELOPE together,
with the exact -target. The JSON source report is emitted even on rejection;
the process returns nonzero. A scan authenticates source bytes at scan time,
not subsequent build-cache contents or actual linker archives; verified-build
remains the enforcement entry point. Symlinks/special files are refused, and
module checksums alone do not establish independent native signing authority.

Unit controls cover scope, unsigned native files in an unused other-target
directory, local replacements, missing downloads, changed signed Go bytes and
the scrubbed resolver environment. The maintained signatures integration suite
constructs a real local file proxy and module cache, fetches setup dependencies,
then renames the proxy away before scanning. An approved downloaded module
passed without any compilable application. An unused unsigned native dependency
and a modified cache entry were rejected; a metadata-only dependency was
reported not-downloaded. These checks passed with CGO_ENABLED=0 and malicious
GOFLAGS ignored. Reproduction: bazel run //:verify -- -suite signatures;
evidence: .work/results/go12610-signatures-scan.

## 2026-11-08: Bounded Bazel consumer verified builds

Added verify.BazelBuild/BazelOptions and CLI verified-build -backend bazel.
Repeat -module importpath=workspace-relative/root for approved, nonoverlapping
local native module subdirectories; the workspace root '.' is deliberately
unsupported. Use -bazel /trusted/bin/bazel, one explicit //package:target,
-policy, repeatable -manifest, -target and a new -o output. For example:

    bao verified-build -backend bazel -bazel /trusted/bin/bazel -C ./consumer \
      -module example.org/native=native -policy /trusted/policy.json \
      -manifest /trusted/native.json -target darwin/arm64 -o ./app //:consumer

Consumer MODULE/BUILD/Starlark definitions, Bazel 8.4.2, rules_go 0.65.0, the
stock Go 1.26.10 SDK and the same-user host remain trusted. Native publisher
BUILD files must be inside the signed module tree. Bao copies and authenticates
these trees before invoking Bazel, seals the snapshot, ignores rc files and
uses new private output/repository/Go caches with disk/remote result reuse
disabled. Repository resolution can download the pinned toolchain/registry
inputs; this backend is not an offline module-cache scan. Bazelisk consumers
must pin 8.4.2 in their own .bazelversion, preserved in the private snapshot.

Preflight aquery allows a small set of ordinary pure-Go actions and validates
their actual trusted builder/packer/bootstrap commands, SDK/stdlib roots and
environments. A mnemonic alone is not executable authentication: explicit
controls reject substituted commands, GO_BINARY/LD_FLAGS overrides, foreign
source paths, and nested lookalike packer paths. Custom actions, external native
repositories, nogo, cgo, race/coverage/plugins, custom build tags and arbitrary
compiler/linker flags are outside this profile. The Go target allowlist is
Darwin arm64/amd64 and Linux arm64/loong64/ppc64le; actual independent consumer
integration here covers Darwin arm64 and Linux arm64 only.

Only compilation_outputs are materialized. rules_go stores export data in .x,
while actual linker .a files contain _go_.o, sN.o assembly and native members,
without __.PKGDEF. A separate archive profile checks native digests and repeated
truncated names, expected Go/assembly members and exact target/SDK headers.
The stock-Go archive checker still requires __.PKGDEF. The selected main/native
archives are copied privately and hashed, and all SDK stdlib archives, the
builder, linker and import metadata are copied for a checked GoLink replay.
Stdlib output is trusted SDK output, not independently publisher-approved;
even unused runtime/race.a may be present. Only after the replay succeeds is a
new executable published. Bao does not execute consumer init/main or native
payloads. This does not turn Bazel analysis into a hostile-Starlark sandbox.

An earlier scratch native-only checker accepted a poisoned _go_.o beside intact
signed native members. Go-object header checks cannot authenticate arbitrary
compiled Go code. The maintained backend therefore always compiles in fresh
private state; it cannot safely reuse ordinary action caches. This complements
the earlier warm stock-Go -toolexec cache-bypass finding rather than assuming
Bazel will invoke cmd/go's hooks.

Initial Darwin analysis failed because rules_cc tried to discover a C compiler
despite pure=on and Bao's invalid CC setting. BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1
selects the empty C toolchain and avoids probing it. Darwin's ordinary rules_go
profile also emits PIE/shared Go assembler/compiler flags; only those exact
Darwin defaults are accepted, not alternate external/shared-library modes.

Maintained integration reproduction on macOS 26.5.2/arm64, SDK 26.5,
Go 1.26.10, Rust 1.99.1 and Bazel 8.4.2:

    bazel run //:verify -- -suite bazel -bazel /path/to/bazel
    bazel run //:verify -- -suite signatures

The new Bazel fixture builds an independent typed-binding consumer without
purego, poisons a real warm shared native archive while signed source remains
unchanged, then successfully links and runs the approved private build natively.
Changed signed Go bytes fail before Bazel, and a reachable Genrule fails during
preflight; both controls check the specific rejection reason, no output and no
consumer initialization. The executable runs only afterward. Final compact
evidence: .work/results/go12610-bazel-consumer-final. The signature/source-scan
suite also passed final explicit rejection controls in
.work/results/go12610-signatures-final.

Concurrent Linux work tested the final CLI backend against an independent
Linux arm64 consumer with all 18 scalar C entries, TLS and scheduler progress.
Native Docker execution passed at GOMAXPROCS=1 and 4. It authenticated two real
native members, privately copied the main/native and 346 stdlib archives, and
produced SHA-256 0fb2aafb49f493414aeea50ba218a2c82c005062224790e182921e4405bb4582.
Logs: .work/bazel-backend-consumer/backend-cli-final.log and final-run-{1,4}.log.
Signed-source changes and reachable custom actions failed without output;
logs remain in .work/bazel-backend-consumer and .work/bazel-backend-bad-graph.
No Bazel amd64/LoongArch/PowerPC runtime pass is claimed.

All nine Bazel tests and ci/check.sh unit passed after backend hardening.
Final CGO_ENABLED=0 go test ./... and go vet ./... also passed using the pinned
SDK with GOENV=off, GOTOOLCHAIN=local and ambient GOROOT unset. An initial direct
SDK invocation inherited the shell's old Go 1.26.5 GOROOT and failed compiler
version checks; removing that environment override resolved it. Bao's scrubbed
verification environments already exclude GOROOT. A final scan unit also checks
that relative -go paths resolve from the caller rather than -C. Actionlint,
shell syntax and diff whitespace checks passed. README additions preserve the
other agent's consumer/developer reorganization. No project commit, push or
publication was performed.

## 2026-11-08: Separate the README's three actors

Corrected the audience model in the earlier "README consumer and developer
instructions" entry. That reorganization grouped library developers with
library consumers. README now has separate sections for consumers of a
Bao-built library, developers producing that library, and maintainers/developers
of Bao itself. Consumers get application calls/builds, runtime compatibility,
pointer lifetimes, TLS finalization, policy approval, dependency scans and
verified Go/Bazel builds. Library developers get CLI setup, native production,
binding generation, supported inputs, distribution, signing and public Bao APIs.
Bao maintainers get source builds, CI, implementation details, diagnostics,
verification suites and helper regeneration. Licensing remains shared.

Split producer signing and Bazel library definitions from consumer approval
and application definitions. Split two mixed build examples so library
production commands and application build commands appear with their respective
actors. Retained the dependency-scan, Bazel-backend and CI documentation added
since the earlier reorganization, and preserved existing section fragments with
aliases where needed. This supersedes the earlier two-audience classification;
no tool or runtime behavior changed.

Verification on Darwin arm64 with Python 3.14.6:
`python3 .work/readme-three-roles/check.py` passed, checking all 40 preexisting
anchors, local targets and fragments in 39 Markdown links, balanced code fences,
and preservation of 23 code examples with the two mixed examples split. It
also checked role-specific command placement and preservation of the prior
journal bytes as an unchanged prefix. `git diff --check -- README.md JOURNAL.md`
passed. Scratch snapshots and the checker are under ignored `.work/`. No
compilation, linkage, native or emulated execution, signing checks, downloads,
or hosted workflows were performed for this documentation change.

## 2026-11-08: Use README heading links without standalone anchors

Removed the README's standalone HTML anchor aliases. Updated maintained links
in README, the Linux runtime example README, and CLI signature-command help to
use fragments derived from the actual Markdown headings. Also corrected the
pointer-rules link to the current "compatibility and pointer lifetimes" heading.
All headings and fenced examples were preserved, including intervening user
edits. This supersedes the anchor-preservation approach in the earlier README
reorganization entries. Earlier journal entries remain unchanged historical
records: their old bindings and verification links now correspond to
[function bindings](README.md#function-bindings-and-native-debug-stripping) and
[consumer verification](README.md#consumer-controlled-signature-verification).

Verification on Darwin arm64 with Python 3.14.6:
`python3 .work/readme-heading-links/check.py` passed, checking 26 heading links
in maintained documentation and CLI help, absence of standalone anchors,
unchanged headings/code examples, and the unchanged prior journal prefix.
`git diff --check -- README.md JOURNAL.md examples/linux_runtime/README.md
cmd/bao/verified.go` passed. No compilation, linkage, runtime or signing checks
were run; the Go source change only updates help text. Scratch inputs and the
checker remain under ignored `.work/`.

## 2026-11-08: Explain optional purego usage for both library actors

Expanded the library-consumer and library-developer README sections to compare
generated typed bindings with runtime registration. Consumers now have separate
calling examples, module requirements and build instructions. Developers have
a mode-selection table covering flags, type information, generated call support
and packaging, plus distribution instructions for each mode. Clarified that
hiding registration behind a library's Go wrapper retains the runtime mode's
purego dependency, while typed generation replaces initialization adapters too.
Typed mode bundles adapted purego bootstrap sources and their notices without
requiring the purego module. Runtime compatibility, pointer ownership, scalar
signature limits and one-bootstrap-per-executable requirements still apply.

Updated the Darwin and Linux example READMEs to distinguish their default
purego consumers from typed calls, and corrected CLI overview help that said
all consumers need Go/purego. The documented behavior was checked against
cmd/bao/build.go, cmd/bao/bindings.go, cmd/bao/tls.go, cmd/bao/linuxelf.go and
bindings/generate.go, including purego-import removal, pointer pinning and
bootstrap emission. Reviewed the maintained bindings integration fixtures and
the earlier "Generated bindings, optimized DWARF inference and stripping"
entry; their historical runtime results were not rerun or claimed anew.

Verification on Darwin arm64 with Python 3.14.6:
`python3 .work/readme-binding-modes/check.py` passed, checking 52 local links,
26 shell snippets with `/bin/sh -n`, two JSON manifests, preservation of prior
headings, unchanged maintainer/verification sections, and the unchanged prior
journal prefix. `git diff --check -- README.md JOURNAL.md examples/README.md
examples/linux_runtime/README.md cmd/bao/cli.go` passed. Scratch inputs and the
checker remain under ignored `.work/`. Shell snippets were parsed, not executed;
no Go/native compilation, linkage, runtime execution, signing, dependency
downloads, or hosted workflows were performed. Generation/runtime behavior is
unchanged; the Go source edit only changes CLI help text.

## 2026-11-08: Runtime caveats with consumer code examples

Added examples directly alongside README's runtime caveats: an explicitly
unsupported mixed-bootstrap import graph, a synchronous byte-buffer call using
the manifest's typed Process function, the equivalent purego call with explicit
pinning and KeepAlive, and locked-thread TLS finalization for both calling
modes. The complete typed example defers finalization before unlocking and
uses the Rust runtime example, whose native workers join before it returns.
Explained that finalization in another goroutine does not select the original
OS thread and that os.Exit/log.Fatal bypass deferred cleanup. Pointer examples
assume the native function retains no buffer address; ownership of returned
native allocations still follows the library API's release contract.

Reviewed bindings/generate.go's pointer pinning, the generated TLS API in
cmd/bao/tls.go, examples/consumer/main.go.tmpl, and the Rust runtime worker joins
and maintained typed consumer. Changed only the Runtime caveats section of
README; headings and other actor instructions remain unchanged.

Verification on Darwin arm64 with Python 3.14.6 and gofmt from Go 1.27.3:
`python3 .work/readme-runtime-examples/check.py` passed, parsing/formatting five
Go snippets and checking 39 local README links, unchanged headings/content
outside the caveats, and preservation of prior journal bytes. Fragment examples
were wrapped in a temporary package/function for syntax parsing.
`git diff --check -- README.md JOURNAL.md` passed. This is syntax/documentation
verification only: no examples were type-checked, compiled, linked, or executed,
and no native or signing checks ran. The mixed-bootstrap snippet is deliberately
unsupported, not a runnable consumer recommendation. The documented Go 1.26.10
runtime profile is unchanged; Go 1.27.3 was used only for syntax formatting.
Scratch inputs and the checker remain under ignored `.work/`.

## 2026-11-08: C++ exception, TLS and static-lifetime probes

The user requested C++ counterparts of the Rust examples, clarifying that the
purpose was to check stack unwinding, TLS, static initialization and finalizers.
Added focused, independent C++20 probes in examples/cpp, with native_control.cpp
as an ordinary C++ executable baseline and a new maintained -suite cpp. The
combined runtime.cpp follows the Rust CoreFoundation/std-thread/exception/TLS
case; isolated unwind.cpp, tls.cpp, static_initializers.cpp and
static_lifetime.cpp prevent one unsupported feature from hiding the others.
All exports retain a C ABI; intentional exceptions are caught inside C++.

Final verification used macOS 26.5.2/arm64, SDK 26.5, Apple Clang
21.0.0 (clang-2100.1.1.101), Bazel 8.4.2, Go 1.26.10 and purego v0.11.3 for
runtime registration. C++ producer flags were -std=c++20 -O2 -g
-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer and an explicit
arm64-apple-macos11 or x86_64-apple-macos11 target. Final supported fixtures
keep normal exception-enabled compilation; an early -fno-exceptions isolation
experiment was superseded and is not the final support claim. The only
diagnostic preprocessor variant removes the nontrivial TLS destructor to isolate
trivial TLS. No Rust sources, embedded helpers or exception-safety checks were
weakened. This work does not add general C++ exception support.

Reproduction from the Bao root:

    bazel run //:verify -- -suite cpp -target darwin/arm64
    bazel run //:verify -- -suite cpp -target darwin/amd64

Compact final evidence: .work/results/cpp-checked-darwin-arm64 and
.work/results/cpp-checked-darwin-amd64. Scratch directories are
.work/verify-cpp-2335594032 and .work/verify-cpp-3630308361, respectively.
The Arm run executed natively; the amd64 run executed through Rosetta 2 on
the Arm host, not native Intel hardware. Linux C++ was not tested.

| Behavior | Bao result on both tested Darwin targets |
| --- | --- |
| Initialized/zero TLS, actual 128-byte TLS address, eight pthread workers plus the caller | PASS |
| Real C++ TLS destructor, access to still-live TLS during destruction, nine drops and nine released blocks | PASS with producer-provided DSO identity and explicit caller-thread TLS finalization |
| C++ global constructor order and startup-thread execution; local static construction once | PASS |
| Compiler-generated global/local static destruction in reverse order 3/2/1 | PASS with a private DSO identity and explicit __cxa_finalize call |
| Repeated static finalization | PASS: no repeated destructor execution |
| Automatic static destruction/libc atexit callbacks when Go main returns | Does not occur; normal native C++ exit controls do execute them |
| Exception crossing two C++ RAII scopes and caught inside C++ | Native C++ controls pass, but Bao rejects the exception metadata |

The DSO identity is the small, separately compiled dso_handle.cpp adapter:
an opaque image-private __dso_handle that a native executable linker ordinarily
supplies. The unsupported unadapted TLS/static cases explicitly reject with
"system SDK does not export ___dso_handle" and publish no generated package.
With the adapter, compiler-generated _tlv_atexit calls use Bao's existing TLS
destructor support. Static destruction uses __cxa_atexit registrations and an
explicit fixture-owned __cxa_finalize(&__dso_handle), not a terminator-table
loader or Go-exit hook. Stop workers and complete their TLS cleanup before
destroying static resources. One native image and no unloading are assumed;
this is an example producer contract, not automatic DSO/runtime management.

For process-exit controls, static_lifetime.cpp registers a C observer before
its first global destructor. A normal C++ return from main then destroys the
local static and globals, and the observer sees 3/2/1. In Go, the same fixture
returns without that observer or those destructors running. Its explicit
shutdown entry point checks the three real destructors and reports once;
repeated calls check idempotence. static_initializers.cpp independently proves
that a registered libc atexit callback runs in the native executable and is
absent when the Go consumer returns. No after-exit in-process assertion was
mistaken for an actual process-exit test.

The stack-unwind and combined runtime controls catch a typed C++ exception and
observe two RAII drops in ordinary native executables. Bao's Arm producer
rejects "compact frame with personality/LSDA needs a dedicated augmented CIE".
The amd64 producer rejects "duplicate compact relocation" in its compact
exception metadata. Both failures occur before Go linkage/execution, with no
published output. Source DWARF used for function-signature inference does not
imply native EH support. Investigated full-DWARF compiler options described in
https://clang.llvm.org/docs/UsersManual.html: the local Apple compiler rejects
dwarf-only, and always did not remove these compact-table boundaries in the
probes. No unsupported flag or discarded exception metadata is presented as a
working C++ unwinding configuration. Scratch investigations remain under
.work/cpp-probe.

The actual TLS-address audit revealed a separate native-control limitation.
An empty inline-assembly barrier prevents the compiler folding an alignas(128)
address check into true. Native Darwin TLS allocations in the destructor
controls failed the 128-byte check on both tested targets while all nine
destructor counters passed (CPP_NATIVE_RESULT:128; TLS_FINALIZED:42). The
trivial native control failed alignment on Arm and passed on Rosetta amd64 in
the final runs. These are recorded as native-control failures, not native
passes or a universal claim about every Darwin allocation. Bao's translated
versions independently passed the actual address and lifecycle checks.

Supported cases each produced fresh Go consumers in runtime registration and
DWARF-inferred fixed-assembly modes, with CGO_ENABLED=0, unavailable CC/CXX/RUSTC
and module networking disabled after setup. Each executable ran at
GOMAXPROCS=1 and 4, then after ad-hoc Hardened Runtime signing and strict
verification. Typed consumers had no purego module in their dependency list.
Input/output hashes, flags, alignment audits and per-case support status are
recorded. Negative controls omit constructor calls, caller-thread TLS cleanup
or explicit static cleanup and require the corresponding state-check failure
and absence of a pass marker. Ordinary native controls link their own CRT
identity, never the Bao-side adapter.

The suite reports CHECKED_WITH_LIMITATIONS, with distinct PASS, UNSUPPORTED and
native-control failure fields. Exit success means the supported checks and
expected boundaries matched, not that C++ unwinding passed. Added the suite to
both Darwin source-CI and packaged-release checks. The new hosted checks have
not been dispatched or claimed as run.

The amd64 constructor probes also found a 13-byte alignment gap between
__text and __StaticInit that the old mergeExecutableText rejected. Updated the
merge to accept exactly section-alignment padding while retaining every symbol
address, instruction byte and relocation offset. Intervening sections, overlap,
non-alignment gaps, oversized alignments and out-of-range merged offsets remain
rejected. Added meaningful layout/relocation and rejection tests. This is a
layout fix, not permission to discard unsupported exception metadata.

After that fix, existing C/Rust binding suites passed on native Darwin Arm and
Rosetta amd64, including Rust std panic cleanup, native threads/TLS teardown,
debug stripping, signing and unwind-negative controls. Evidence is under
.work/results/cpp-regression-bindings-{arm64,amd64}. The translator unit target
passed fresh. README and examples/README now link the C++ scope and producer
recipe; existing actor-oriented edits and user files were preserved.

Final ci/check.sh unit completed with all nine Bazel targets freshly executed,
CLI/verifier/helper/release-tool builds, Go-version consistency and SDK
go vet ./... passing. Actionlint 1.7.12, bash -n ci/*.sh release/*.sh and
git diff --check passed. No commit, push, workflow dispatch or publication was
performed for the C++ work.

## 2026-11-08: Linux amd64 ELF backend and pinned Clang compiler image

The user explicitly expanded the Linux C++ work to support amd64. Added the
Linux amd64 translator path in linuxelf/amd64.go and the ELF machine, sysroot
and native-helper routing needed by the existing pipeline. Inputs remain
little-endian ELF64 relocatable objects. Go 1.26.10's stock internal linker
handles the retained PC32, PC64, PLT32, absolute 64-bit and GOTPCREL relocation
forms. Imported absolute pointers use the existing writable native-data fixup
mechanism before constructors and unwind registration. Executable pages are
never patched. Missing optional weak addresses stay NULL; a required import in
another object overrides a weak declaration.

Checked GCC/Clang general-dynamic and local-dynamic TLS sequences now address
image-private 16-byte descriptors through ordinary RIP-relative PC32 LEAs.
The original RDI argument setup, call instructions and GCC relaxation padding
are preserved. GD descriptors select the symbol's template offset; LD
descriptors select the block base, with DTPOFF32/64 references folded to checked
template offsets. The local symbols are bounds-checked before offset addition.
The native resolver uses the original shared tls.c implementation and ordinary
SysV C calling convention. LLVM's TLS_addr64/TLS_base_addr64 definitions model
the C caller-save GPRs and FP/SIMD registers as clobbered:
https://github.com/llvm/llvm-project/blob/release/19.x/llvm/lib/Target/X86/X86InstrCompiler.td.
No additional amd64 resolver assembly was required. The existing private DSO,
C++ TLS destructor ordering, explicit current-thread finalization and retained
pthread-cleanup storage contracts remain in force.

Clang emits .eh_frame as SHT_X86_64_UNWIND (0x70000001). The backend accepts that
processor-specific type only for bounded .eh_frame data without executable,
TLS or compressed flags, then retains its bytes as ordinary unwind data.
Other processor-specific sections remain unsupported. The GCC ARM64 TLSDESC
resolver-register recognition added during the C++ investigation was preserved.

The initial amd64 profile requires the checked direct-PLT GD/LD access forms.
Initial-exec, local-exec, GNU2 TLSDESC, indirect-GOT TLS calls, relocations in TLS
templates and external-image TLS remain outside this profile. Native IFUNC
definitions and arbitrary DSO load/unload behavior retain their earlier
boundaries. These restrictions are explicit errors rather than TLS references
being passed through to Go's own TLS model.

The original native helper was compiled with GCC 14.4.0 using
`-O2 -fPIC -fno-omit-frame-pointer -c`. The maintained cmd/bao-native generator
now accepts linux/amd64 and reproduced its embedded runtime.bin byte-for-byte:
SHA256 a13ae5de96aa775116854346fbd3e726b80d536b04777a752ba9d33d60c4c3f8.
The shared tls.c source hash remains
50b516922dd08c77a52e9490117cae19275b982a2c98c3ea614df0a817d1a7df.
The generator was cross-built with Go 1.26.10 and run in the pinned GCC amd64
container through QEMU 7.0.0 on the ARM64 Colima VM. Its clean staged root and
log are under .work/linux-amd64-backend/regenerated and helper-regeneration.log.
The actual regeneration command was:

    docker run --rm --pull=never --platform linux/amd64 --network none \
      --read-only --tmpfs /tmp:rw -v "$PWD/.work/linux-amd64-backend:/work" \
      bao-linux-cpp-gcc:20261108-amd64 /work/bao-native-linux-amd64 \
      -root /work/regenerated -target linux/amd64

With the pinned Go 1.26.10 SDK, `CGO_ENABLED=0 go test ./linuxelf` and
`go vet ./linuxelf` passed. New semantic tests cover GD/LD offsets and retained
instruction bytes, unsupported TLS models, malformed sequences, symbol-value
overflow, missing-weak GOT semantics, strong-over-weak imports, writable dynamic
pointer fixups and the narrow Clang unwind-section normalization. Provenance
tests now include the amd64 helper. These backend checks are separate from the
complete consumer execution evidence recorded by the integration suite.

Added testdata/toolchains/linux-cpp-clang.Dockerfile for both Linux architectures.
It derives from official GCC index
sha256:a257536c9b7a0ee193c1880f2d691358d2c9760ef0ede3ee741aa243789743c7
and installs clang-19=1:19.1.7-3+b1 from the fixed Debian snapshot
20261108T000000Z, without recommended packages. The clang++ command is a symlink
to Debian Clang 19.1.7; producer flags explicitly select
`--gcc-toolchain=/usr/local -stdlib=libstdc++`. This adds no Python workflow
dependency. Both architecture images built successfully, and all five ordinary
C++ controls passed with Clang and libstdc++: ARM64 executed natively in the
Linux VM; amd64 executed through its registered QEMU 7.0 interpreter.
Compiler/control logs and source hashes are under
.work/cpp-linux-clang/{arm64,amd64}. Full Bao execution results follow in the
integration evidence.

## 2026-11-08: Linux C++ GCC/Clang execution on arm64 and amd64

Added the self-contained examples/cpp_linux/runtime.cpp counterpart and portable
support for the focused examples/cpp exception, TLS and static-lifetime sources.
The complete fixture checks argc/argv/environ constructor arguments and numeric
priority, startup-thread construction, imported glibc data, pointer addends,
actual 128-byte storage/TLS alignment, allocation, a native qsort callback,
eight C++ threads, initialized/zero TLS, nine C++ thread-local destructors,
later pthread cleanup with retained TLS addresses, a typed exception through
two RAII cleanup scopes, and explicit reverse-order static destruction 3/2/1.
Exceptions remain entirely inside C++; no exception crosses a Go frame.

All four GCC/Clang and arm64/amd64 combinations passed actual Bao translation,
stock Go internal linkage and execution, with both purego runtime registration
and DWARF-inferred fixed assembly bindings. This supersedes the earlier release
entry's statement that Linux amd64 is only a CLI host (near line 753), and the
intermediate amd64 preflight's expected unsupported-target result. Those older
logs describe the implementation before the user authorized the amd64 backend.
The new result covers the checked C++ profile; it does not establish Linux
amd64 Rust std, libc++, or arbitrary compiler/TLS-model compatibility.

Execution used a macOS arm64 host, native aarch64 Colima Linux Docker VM and
Go 1.26.10 darwin/arm64. Linux arm64 executables ran natively in that VM. Linux
amd64 executables actually ran under its registered QEMU 7.0.0 interpreter,
including the Linux producer CLI; no physical amd64 Linux run is claimed here.
Compiler versions were g++ 14.4.0 and Debian Clang 19.1.7 (3+b1), GNU ld 2.44,
glibc 2.41-12+deb13u4 and GCC's libstdc++ runtime. Both Clang producer commands
explicitly used --gcc-toolchain=/usr/local -stdlib=libstdc++.

Reproduction from the source root (Bazel 8.4.2; preparation requires network):

    for arch in arm64 amd64; do
      docker build --platform "linux/$arch" \
        -f testdata/toolchains/linux-cpp.Dockerfile -t "bao-cpp-gcc:$arch" .
      docker build --platform "linux/$arch" \
        -f testdata/toolchains/linux-cpp-clang.Dockerfile -t "bao-cpp-clang:$arch" .
      bazel run //:verify -- -suite cpp -target "linux/$arch" \
        -cxx g++ -image "bao-cpp-gcc:$arch"
      bazel run //:verify -- -suite cpp -target "linux/$arch" \
        -cxx clang++ -image "bao-cpp-clang:$arch"
    done

Producer flags were -std=c++20 -O2 -g -fPIC -fno-omit-frame-pointer -pthread,
plus -mno-outline-atomics and GCC -mtls-dialect=desc on arm64, or
-march=x86-64 -mtune=generic on amd64. Scalar C controls used -std=gnu11 -x c:
strict c11 hides usleep in glibc and failed the original compile control, so
that failure was corrected rather than ignored. GCC outline atomics were
disabled on arm64 because their private static libgcc helpers are outside the
dynamic system-export profile. The ARM TLSDESC recognizer now accepts a checked
matching LDR/BLR resolver register instead of assuming x1; GCC also emits x2/x3.
Tests reject mismatched registers, wrong bases and nonconsecutive sequences.

Final compact results and logs are under
.work/results/cpp-linux-{gcc,clang}-{arm64,amd64}-final. All five independent
ordinary C++ executable controls passed in each run. Fresh Go consumers used
CGO_ENABLED=0, invalid native compiler paths and offline module resolution
after checksum-verified purego setup, and ran read-only/network-disabled at
GOMAXPROCS=1 and 4. Each typed consumer had no purego module dependency; native
source debug sections were stripped while runtime unwind data was retained.
Source/archive hashes, compiler flags, image identities, executable hashes and
native section-alignment audits are recorded. The full fixture source hash is
32da9c0d0b0a2e560ce52a16811b42c5e732a15b4a2e2555859ab657b08ca62e.

Meaningful negative controls omitted unwind registration (native termination),
constructor calls (native-state failure), caller-thread TLS finalization and
explicit static finalization (their respective state-check failures). Each
required nonzero exit and no PASS marker. Ordinary C++ return-from-main controls
ran their static finalizers/exit callback; the Go exit controls omitted those
markers. Explicit finalization ran static destructors once in 3/2/1 order,
and a repeated call remained idempotent. Scalar C ABI controls independently
passed integer/FP register exhaustion, mixed/narrow stack arguments, pointer
results, uint32 extension, TLS and Go scheduler-progress checks on all four
compiler/architecture combinations.

Linux uses Bao's existing private image DSO identity, not the Darwin producer
adapter. The portable exit observer directly uses __cxa_atexit on Linux because
glibc's atexit wrapper is supplied by libc_nonshared.a rather than its dynamic
symbol table. The imported-data control uses glibc's global __environ definition
instead of its weak environ alias, which the ordinary GNU native link control
rejected for this absolute relocation. Neither workaround removes the lifecycle
checks. The native control resolves libstdc++ and libgcc_s from /usr/local/lib64;
the translator's symbol lookup indexes the image's distribution shared-library
exports. Symbol-version equivalence across other runtime versions is unverified.
The verifier also records native-control ldd and translated-Go readelf -d
diagnostics. These commands were checked on both architectures after adding
them; the four complete runs above preceded that diagnostic-only addition.
ldd trace mode on the emulated Go ELF exited 139, although direct execution
passed, so it is not used as a required Go-executable runtime check.

The existing Linux arm64 typed C/Rust suite passed fresh:
`bazel run //:verify -- -suite bindings -target linux/arm64`, results under
.work/results/cpp-linux-rust-arm64-regression. This reran optimized-debug scalar
C and Rust 1.99.1 std consumers, caught panic/RAII cleanup, eight native threads,
nine TLS destructors and stripping checks. The shared C++ source changes also
passed the documented Darwin suites on native Arm and Rosetta amd64, including
signing checks, under .work/results/cpp-darwin-{arm64,amd64}-portable. Their
CHECKED_WITH_LIMITATIONS status preserves the prior Darwin compact-exception
metadata and native TLS-alignment boundaries; Linux success does not erase them.

Source CI now has distinct Linux arm64 and amd64 jobs, each testing GCC and
Clang on a matching native hosted runner. Packaged-release checks likewise use
both Linux architectures and the selected packaged CLI. Exact CI result keys
include the new suite identity; its architecture-isolation unit test passed.
Hosted workflows were edited and linted, not dispatched or claimed as executed.
All nine Bazel unit targets passed freshly, source builds and go vet ./... passed,
and actionlint 1.7.12, shell syntax and git diff --check passed. No commit, push,
workflow dispatch or publication was performed. Scratch artifacts remain in
ignored .work/ and all earlier journal entries remain intact.

## 2026-11-08: C++ on loong64/ppc64le, gated by the Rust examples

Extended the maintained Linux C++ verifier to loong64 and ppc64le ELFv2. The
cross compiler and Bao producer run on the arm64 Linux Docker VM; ordinary
C++ controls and translated Go consumers run explicitly through QEMU with
-L /usr/<target-triple>. This separates producer-image architecture from guest
architecture and records the emulator version. Both existing cross backends
handled the new C++ inputs without further translator or native-helper changes.

The user required the Rust examples to gate this work. Source CI and packaged
release checks now require the independent Rust std runtime suite and typed
C/Rust binding suite to pass for each target, in the same cross image, before
running either C++ compiler. A failed Rust command prevents a successful job
and release publication. Standalone -suite cpp still measures C++ only; it
does not stand in for those separate mandatory Rust gates.

The maintained linux-cross.Dockerfile retains Rust 1.99.1, both installed Rust
standard-library targets and QEMU 10.0.13. It adds matching GCC cross C++
compilers (14.2.0-19cross1) and Clang 19.1.7 (1:19.1.7-3+b1), and fixes all
APT resolution to snapshot.debian.org at 20261108T000000Z. Target glibc sysroot
packages are 2.41-11cross1, libstdc++ is 14.2.0-19cross1, binutils is 2.44-3,
and QEMU is 1:10.0.13+ds-0+deb13u1. The actual ARM image used for every gate was
sha256:65eb3617183d17bb3d73b83ff220cf3f9336ef5b061d87d0d949eb85b68ebb7f.
The Dockerfile's original pinned Rust base digest is unchanged.

Local checks used macOS 26.5.2 arm64, a native aarch64 Colima Linux VM, Bazel
8.4.2 and stock Go 1.26.10. Both Rust runtime gates and both typed-binding gates
passed freshly in this image before launching C++ verification. They exercised
actual guest panic unwinding with two RAII drops, eight Rust threads, nine TLS
destructors, later pthread cleanup, constructors, data fixups, alignment and
libc callbacks at GOMAXPROCS=1/4. Removing unwind registration still linked and
then failed as expected. PowerPC's full VSX/TOC preservation and missing-register
restoration negative controls also passed. Typed C/Rust checks retained native
unwind metadata after source debug stripping and required no purego module.

GCC and Clang then passed all five C++ cases on both architectures: caught
exception/RAII unwinding, initialized/zero/128-byte TLS and nine destructors,
static construction, explicit reverse-order static destruction, and the complete
runtime counterpart including later pthread cleanup. All twenty ordinary C++
controls passed independently. Each Bao case passed both runtime registration
and DWARF-inferred assembly bindings, with CGO_ENABLED=0 and GOMAXPROCS=1/4.
Negative controls for FDE registration, constructors, TLS finalization and static
finalization failed their expected checks without a PASS marker. Additional
scalar ABI controls passed integer/FP spills, mixed/narrow arguments, pointers,
uint32 extension, TLS and Go scheduler progress for all four compiler/target
combinations. Input/source hashes, section alignment, no-RWX checks, debug
stripping and executable/image hashes are recorded in the compact results.

Cross producer flags were -std=c++20 -O2 -g -fPIC -fno-omit-frame-pointer -pthread.
GCC uses <target-triple>-g++; Clang uses --target=<target-triple>
--gcc-toolchain=/usr -stdlib=libstdc++, selecting the matching cross libstdc++.
No extra --sysroot or manually supplied header/linker paths were needed for
Clang. GNU target ld combines the archive and the Bao sysroot is
/usr/loongarch64-linux-gnu or /usr/powerpc64le-linux-gnu. Compilation/execution
containers disable networking; execution mounts are read-only with invalid
native compiler paths. Consumers do not extract/load an application DSO.

Reproduction from Bao (build preparation needs network):

    docker build --platform linux/arm64 -f testdata/toolchains/linux-cross.Dockerfile \
      -t bao-cpp-cross:20261108 .
    for arch in loong64 ppc64le; do
      bazel run //:verify -- -suite linux-cross -target "linux/$arch" -image bao-cpp-cross:20261108
      bazel run //:verify -- -suite bindings -target "linux/$arch" -image bao-cpp-cross:20261108
      for cxx in g++ clang++; do
        bazel run //:verify -- -suite cpp -target "linux/$arch" -cxx "$cxx" -image bao-cpp-cross:20261108
      done
    done

Results/logs are under .work/results/cpp-cross-rust-{runtime,bindings}-{loong64,ppc64le}
and .work/results/cpp-cross-{gcc,clang}-{loong64,ppc64le}; independent ordinary
control results are under .work/cpp-cross/{loong64,ppc64le}-{gcc,clang}.
These are successful linkage and actual QEMU 10.0.13 guest execution, not
physical LoongArch/PowerPC hardware tests. The existing experimental status,
ELFv2-only PowerPC ABI, checked GD/LD TLS forms and single-image/process-lifetime
boundaries remain. Explicit TLS/static finalization is required, exceptions
stay inside C++, and libc++/LLVM libunwind and arbitrary TLS/DSO models remain
unverified or rejected. The prior arm64/amd64 results are unchanged historical
evidence; this entry extends the C++ matrix to the two additional profiles.

All nine Bazel unit targets passed freshly. The verifier built successfully,
actionlint 1.7.12, shell syntax and git diff --check passed. CI/release YAML was
updated and linted; no hosted workflow was dispatched or claimed as executed.
No commit, push or publication was performed. No earlier journal entry or
unrelated user edit was rewritten.

## 2026-11-08: Reuse source CI and remove duplicate release test suites

The user observed duplicate CI/release execution and ineffective result reuse,
then requested invoking the CI part from release. Release already used the
reusable ci.yml, but also repeated unit and full native integration suites in
its build/platform jobs. The standalone branch CI and release's called CI also
started concurrently on a cold result cache. Downloaded logs from successful
source run 42458725026 and release run 42458725002 for commit
785cc5d40b633f39dfbc8d60ef1ce6e86fe07ad7 demonstrate identical result keys:
Darwin arm64 restored at 07:25:23 UTC in source CI and 07:25:24 in release CI,
both before either run saved success. These were concurrent cold misses, not
different content keys. Both workflows eventually succeeded and publish was
skipped. This supersedes earlier statements that this source's hosted CI had
not run, while not claiming the refactored workflow below has run on GitHub.
Raw logs are .work/ci-cache-{source,release}-hosted.log.

Kept ci.yml as release's sole full-test gate. Added ci/await-source.sh and a
small read-only coordination job before the reusable call. It waits for the
matching default-branch push CI for the exact candidate commit to finish and
populate its cache, accounting for a short workflow-creation race. A failed,
cancelled, mismatched or timed-out source run fails the coordination step. No
matching branch run falls back to normal reusable CI after the grace period.
API errors fail closed. The helper only queries the constrained CI workflow,
candidate SHA, default branch and push event; it does not dispatch or alter runs.

A successful source run is not itself treated as an exact cache hit. Each
called CI runner still computes and validates its original Git-tree/suite/
runner-image key, with the existing bounded success-record parsing and trusted
ref restrictions. Missing/evicted records, changed image versions and unknown
runner identities continue to execute fresh checks. GitHub allows tag runs to
restore default-branch caches, while sibling refs remain isolated:
https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching.
Read-only cache inventory confirmed the matching keys had been saved on main.
The live completed-run lookup returned the expected source run; no new hosted
workflow was dispatched to demonstrate the revised cache-hit path.

Removed repeated unit, Rust/framework, C++, binding and signature suites from
release build/platform jobs. Source CI still includes all of them, including
the same-image Rust runtime/typed-binding gates before cross C++ checks. This
supersedes the preceding C++ entries' choice to rerun those full suites against
packaged CLIs. Release continues to require every reusable CI job, its archive
checksums, metadata and attestation, and all fresh packaged smoke checks before
publication. It does not run full integration a second time after accepting a
validated source CI result.

Added -suite release-smoke and testdata/release_smoke.c for fresh selected-CLI
coverage. The selected executable itself builds a native archive into typed
bindings, then a stock Go 1.26.10 consumer links with CGO_ENABLED=0 and executes
the native constructor, C call, initialized TLS and explicit cleanup. Exactly
one native TLS block must be freed. The suite records selected-CLI, fixture and
consumer hashes and has no purego module dependency. It checks the CLI machine
matches the selected target and never rebuilds a substitute. For cross Linux,
both the LoongArch/PowerPC CLI and consumer execute under explicit QEMU -L,
with an explicit target -ld to avoid the emulated CLI selecting the host's ld.
Consumer containers are read-only/network-disabled with invalid compiler paths.
Darwin additionally signs the consumer ad hoc with Hardened Runtime options,
verifies the signature strictly and runs it again. Full exception, destructor,
register-preservation and negative-control coverage remains in source CI.

Verification used macOS 26.5.2 arm64, SDK 26.5/Apple Clang 21, Bazel 8.4.2,
Go 1.26.10, native arm64 Colima Docker, GCC 14.4 native compiler images and the
maintained GCC 14.2/QEMU 10.0.13 cross image. Local amd64 Linux execution used
QEMU 7.0.0 and Darwin amd64 used Rosetta. No physical LoongArch/PowerPC execution
is claimed. Unit tests with a fake read-only gh executable cover running-to-
success, delayed creation, no-run fallback, failure/cancellation, timeout,
foreign commit/branch/URL, unknown status and API errors. The existing cache
identity/corruption/dirty-source controls remain intact and passed.

Built all six distribution targets, then exercised real archives with:

    env -u GOROOT BAZEL="$PWD/.work/tools/bazel" \
      BAO_BAZEL_ROOT="$PWD/.work/bazel-root" \
      BAO_RELEASE_VERSION=v0.0.0 \
      BAO_RELEASE_COMMIT=0000000000000000000000000000000000000000 \
      SOURCE_DATE_EPOCH=1794110194 \
      bash release/build.sh .work/release-refactor-dist

These are local test artifacts built from the working tree with deliberately
all-zero commit metadata, not publishable source attestations. All seven
SHA256SUMS entries passed. Extracted all six archives and ran:

    bazel run //:verify -- -suite release-smoke -target <os>/<arch> \
      -bao "$PWD/.work/release-refactor-extracted/bao_v0.0.0_<os>_<arch>/bao" \
      -image <matching-compiler-image>

Omit -image on Darwin; native Linux used bao-smoke-gcc:arm64/amd64 from the
pinned GCC Dockerfile, and cross Linux used bao-smoke-cross:20261108 from the
maintained cross Dockerfile. Every extracted-archive smoke passed, with records
under .work/results/release-refactor-archive-<os>-<arch>. Supplying the arm64 CLI
for a loong64 smoke failed before translation with the required selected-target
error. All nine Bazel targets passed freshly via ci/check.sh unit, builds and
go vet ./... passed, and actionlint 1.7.12, shell syntax and git diff --check
passed. No commit, push, workflow dispatch or publication was performed.

## 2026-11-08: Experimental Windows COFF and real MSVC under Wine

The user requested Windows amd64/arm64 support using Sable's strategy, separate
VC++, Clang and MinGW checks, and actual downloaded Microsoft tools under Wine.
Read Sable at c171bd8596481864a103bbb3269e36cb98dba5e1: its local Wine aid and
native Windows CI are useful validation precedents, but its cgo/external-linker
implementation does not establish Bao's CGO_ENABLED=0 behavior. Kept Bao's
internal-linking requirement and added an independent bounded COFF backend.

The public pecoff package parses ordinary amd64/ARM64 COFF with debug/pe, selects
archive members by exported-function roots and undefined-reference closure,
namespaces native globals, strips debug information without changing the source,
and returns import, initializer, alignment and unwind plans. The CLI builds
Windows packages without a native partial linker and rejects -ld on this path.
inspect reports structural COFF object/archive information; targets and doctor
describe the experimental profile. Windows SDK/sysroot flags are rejected.
DLL imports use private IAT symbols and explicit function tail stubs. Additional
system DLL function mappings require -windows-import Function=system.dll.

Original fixed-signature assembly uses Win64's ordinal register slots, 32-byte
shadow space and stack arguments, or Windows ARM64's fixed scalar register
banks. Go's Windows runtime.cgocall supplies the system-stack transition without
a fakecgo bootstrap. Explicit manifests and runtime PureGo registration both
work; optimized GNU-flavor Clang COFF with DWARF can infer signatures before
stripping. CodeView emitted by MSVC/clang-cl is deliberately not interpreted as
DWARF; those fixtures use independently maintained signature manifests.

Several real compiler/linker failures shaped this implementation:

* Bare Go dynamic imports did not satisfy __imp_ relocations. Naming the IAT
  cell itself privately avoids unresolved references and an external-linker
  fallback. No consumer C compiler participates in the successful builds.
* On amd64, registering a dynamic function table for code inside Go's PE image
  did not make RtlLookupFunctionEntry find it: the image's static exception
  directory takes precedence. Keeping canonical .pdata/.xdata lets stock Go
  merge the native records. ARM64 retains image-relative records in private
  sections and registers them with RtlAddFunctionTable.
* Freestanding Clang requires explicit -funwind-tables for these nonleaf
  fixtures. Omitting it did not provide meaningful unwind-lookup evidence.
  MSVC fragments .pdata/.xdata and repeats section names/COMDAT associations;
  the backend merges SEH fragments, preserves symbol/relocation offsets, and
  makes other selected sections private after rejecting duplicate definitions.
* MSVC has decorated local symbols, REL32_1..5 addends, .chks64/.voltbl metadata,
  and @comp.id/@vol.md absolute metadata symbols which stock Go cannot load as
  native data. These are normalized or stripped explicitly; @feat.00 remains
  recognizable to Go. Keeping debug payloads still removes incompatible
  compiler identity symbols. Data alignment is checked at actual runtime
  addresses; end padding supports Go's size-inferred alignment up to 32 bytes.
  Text alignment beyond 16 and data alignment beyond 32 fail explicitly.
* MSVC 17.14+ outlines ARM64 atomics by default, introducing CRT helpers such
  as _InterlockedExchange. The no-CRT fixture explicitly compiles with
  /forceInterlockedFunctions-. This is not implicit CRT support. Microsoft's
  explanation: https://devblogs.microsoft.com/cppblog/introducing-the-forceinterlockedfunctions-switch-for-arm64/.

Added examples/windows_runtime: independent Cargo no_std staticlib with a real
atomic RAII drop and Win32 call, C initialized data/constructor/native unwind
lookup, C++ static initialization and normal-scope destruction, scalar ABI
fixtures and unsupported TLS/throw-catch inputs. These do not exercise native
TLS, full Rust std, exception propagation or process finalization successfully.
The tests require explicit rejection of those boundary fixtures without an
output package. Also reject weak externals, common symbols, duplicate selected
global definitions, unsupported initializer families/priorities, malformed
initializer pointer tables and unsupported relocations. MinGW GCC -m32 really
produces i386 COFF, which must fail with the Windows/386 unsupported error.

Downloaded Microsoft packages through HTTPS installer catalogs into ignored
.work/msvc, extracted VSIX ZIP payloads with a scratch standard-library Go
program, and retained the original packages and Microsoft notices/license pages.
No Python was used to download, extract, translate or test. The msvc-wine Python
script was read as reference only. This is a local toolchain installation, not
a Bao-distributed compiler or SDK. Build Tools license URLs from the catalogs:
https://go.microsoft.com/fwlink/?LinkId=2179911 (2022) and
https://go.microsoft.com/fwlink/?LinkId=2327714 (2026).

Download trust limitation: the VS 18 stable channel advertised a catalog of
31,256,199 bytes with SHA-256 6feafaf09375b7a7534a79845739c8af4a61041fa2cf4b2d86b56a764c734b7f,
but the official HTTPS URL repeatedly delivered 18,407,518 bytes with SHA-256
417b8d3fee577bdb0e192835692446de51b4626526e4b555162fd9c2fca7dff1.
Whitespace/line-ending reconstruction did not resolve this mismatch. The
compiler payloads were checked against the hashes in that downloaded HTTPS
catalog, but this is not a validated channel-to-catalog hash chain or an
Authenticode/signing check. No automatic catalog downloader that silently
accepts the mismatch was added to Bao. Raw catalogs/headers remain in
.work/windows-probe. The production compiler payload checksums are:

    Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.base.vsix
      f4ad3cee4ef18e9f36382399261de27be6910ab3467178d7e687377ec841306d
    Microsoft.VC.14.44.17.14.Tools.HostX64.TargetARM64.base.vsix
      ea6756748c60943b99235806bb74b8d878efe5d7ab1194fd3d17213df60c2d91
    Microsoft.VC.14.44.17.14.CRT.Headers.base.vsix
      852382a9aa73502b7849c1bcadfb603ba7175c4e8b60e6aba03c7de711d4ece5

English compiler-resource payloads were also hash-checked. A preliminary
19.52.36815 PREVIEW compiler was run and its ARM64 suite passed, but the final
production matrix below uses 19.44.35229 (installed directory 14.44.35207).
The user's visible vctip.exe error dialog came from the Microsoft helper under
Wine. Renamed only this task's extracted vctip.exe copies to vctip.exe.disabled;
this matches the upstream workaround at
https://github.com/mstorsjo/msvc-wine/blob/master/install.sh#L92-L97.
ci/msvc-wine.sh now refuses to launch an installation with that helper enabled,
then adapts Unix source/output/include paths without mutating the installation.
No successful test result is inferred from a crashed compiler-helper dialog.

Final verification environment: macOS 26.5.2 arm64, Apple Clang 21.0.0
(clang-2100.1.1.101), MSVC 19.44.35229 x64-hosted x64/ARM64 compilers,
MinGW-w64 GCC/G++ 16.1.0, Rust 1.99.1, Go 1.26.10 and Bazel 8.4.2.
Windows amd64 executables ran through Wine 11.21 on Apple Silicon/Rosetta.
Windows ARM64 executables ran in native arm64 Colima Linux with Wine
10.0~repack-6, from the GCC image pinned at
sha256:2bafb163aaa91eef7856f17ff0abf69144ebe3218a4eea75c043bb3043b9ecfa
and Debian snapshot 20261108T000000Z. These are Wine execution results, not
native Windows execution. The task-owned image-hold container was removed;
unrelated containers, images and installations were preserved.

Seven final fresh producer/consumer legs passed: Clang GNU and clang-cl on both
architectures, real MSVC on both architectures, and MinGW GCC/G++ on amd64.
Each compiled the changed native inputs and built CGO_ENABLED=0 consumers at
GOMAXPROCS=1 and 4. Typed modes checked integer/FP/mixed/narrow register and
stack arguments, pointers, return values and scheduler progress during a native
blocking call. Runtime registration checked integer C/C++ calls. Every leg also
built and executed the Cargo no_std fixture. Disabling constructors must still
link and then fail; disabling ARM64 table registration or removing amd64
exception-directory participation must still link and fail native lookup.
Unit tests also check section/symbol remapping, SEH merge/addends, source-byte
immutability, archive dependency selection and duplicate-definition rejection.

Reproduction for the real MSVC x64 leg (substitute the downloaded installation
and an available arch-neutral ar; ci/msvc-wine.sh requires the helper rename):

    export MSVC_TOOLS="$PWD/.work/msvc/root/VC/Tools/MSVC/14.44.35207"
    export MSVC_ARCH=x64
    export WINE="$PWD/.work/tools/wine/Wine Devel.app/Contents/Resources/wine/bin/wine"
    export WINEPREFIX="$PWD/.work/windows-wine/prefix-amd64"
    env -u GOROOT .work/tools/bazel --output_user_root="$PWD/.work/bazel-root" \
      run //:verify -- -suite windows -target windows/amd64 \
      -windows-driver msvc -windows-cc "$PWD/ci/msvc-wine.sh" \
      -windows-cxx "$PWD/ci/msvc-wine.sh" -windows-ar x86_64-w64-mingw32-ar \
      -windows-runner "$PWD/.work/windows-wine/run-amd64.sh"

ARM64 uses MSVC_ARCH=arm64, windows/arm64 and the scratch Docker Wine ARM64
runner. Clang/clang-cl use -windows-driver clang or clang-cl and host clang/
clang++; MinGW uses -windows-driver mingw and x86_64-w64-mingw32-gcc/g++.
Compact final records and logs are .work/results/windows-<arch>-<driver>-final.
For example, original MSVC x64/ARM64 archives have SHA-256
66f8a0393b567bfd2ba329b87103396100716ed8f59120d72f428f735403f633 and
07d21055cd757345deb632996cd3387ac4b36ef8f5546ef665d0fc7ff50492e6.

All ten Bazel unit targets passed freshly; go vet ./..., actionlint 1.7.12,
shell syntax and diff whitespace checks passed. The shared scalar fixture's
Darwin arm64 binding suite passed freshly. Linux arm64 initially completed its
C checks in the GCC/Wine image, then stopped because rustc was absent: that
attempt was not a suite pass. Restored the pinned Rust image
sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd
and reran -suite bindings -target linux/arm64 completely. Native Linux C and
Rust execution passed, including caught panic, two RAII drops, eight threads,
nine TLS destructor calls, zero live TLS blocks and stripped-debug negative
controls. Records: .work/results/windows-regression-darwin-bindings and
.work/results/windows-regression-linux-bindings-complete.

Source CI now has separate native Windows amd64/arm64 compiler gates using the
matching VC developer environment, pinned Go setup and Rust component; x64 also
requires the real MinGW leg. These participate in the existing exact source/
suite/runner-image result cache and reusable release CI gate. The new native
Windows jobs have not run or been dispatched locally, so all Windows support
remains experimental. Release archives still cover six Darwin/Linux CLI hosts;
Windows CLI source builds are distinct from publishing Windows distributions.
Full Rust std, CRT/TLS/finalizer support and C++ exception execution on Windows
remain unsupported. No commit, push, workflow dispatch or publication occurred.

Final CLI checks also cross-compiled cmd/bao with CGO_ENABLED=0 for both
windows/amd64 and windows/arm64 using Go 1.26.10; file identified PE32+
x86-64 and AArch64 executables respectively. This establishes compilation,
not native Windows execution of those CLIs. COFF inspect was exercised against
the real MSVC archive with its absolute scratch path. The Wine helper guard's
negative control used a disposable installation containing only a vctip.exe
sentinel and WINE=/bao-must-not-launch: it exited 2 before starting Wine.

## 2026-11-08: Native Windows CI integration clarification

The user clarified that CI should use native Windows VMs, while Wine remains a
local aid. No MSVC downloader, Wine job or Wine-specific vctip workaround was
added to hosted CI. Confirmed the existing native matrix uses windows-2025
(amd64) and windows-11-vs2026-arm (ARM64), with installed Visual Studio/LLVM,
Go 1.26.10 and Rust 1.99.1. Native VC developer environments are selected with
vswhere/VsDevCmd for the matching host/target architecture. Both jobs run the
Clang, clang-cl and actual cl.exe profiles; amd64 also runs MinGW GCC/G++ and
the real 32-bit object rejection control. Executables run directly with no
-windows-runner option. Native checks retain constructors, unwind lookup and
negative controls, scalar ABI, runtime registration and Cargo no_std coverage.
The existing exact source-tree/suite/runner-image cache covers both native jobs,
and release requires their reusable source CI result.

Review found a native Windows portability bug: os.Environ commonly supplies
Path, while the verifier inserted PATH into a case-sensitive map. Iterating
that map could unpredictably discard the VC/Cargo search paths in child
processes. Canonicalize Windows environment keys before applying overrides;
preserve Unix case sensitivity. Added a regression test with mixed-case Path,
GoRoot and SystemRoot, included it in both Bazel's test suite and native CI,
and added an explicit native Windows Go host/architecture check in ci/check.sh.
The runner labels and installed compiler inventories were verified against
https://docs.github.com/en/actions/reference/runners/github-hosted-runners and
https://github.com/actions/runner-images/blob/main/images/windows/Windows11-VS2026-Arm64-Readme.md.
Hosted execution is still pending; checking configuration does not establish a
passed native Windows run. No commit, push or workflow dispatch was authorized.

Local verification on macOS arm64 with Go 1.26.10/Bazel 8.4.2: all eleven
unit targets passed freshly, including the Windows environment regression;
go vet ./..., actionlint 1.7.12, shell syntax and git diff --check passed.
The verifier's test binary also compiled for windows/arm64 with CGO_ENABLED=0;
it was not executed on Windows here. Logs are .work/windows-native-ci-*.log.

## 2026-11-08: Windows per-platform documentation

Added a Windows amd64/ARM64 subsection under README's Per-platform details,
alongside Darwin and Linux. It describes COFF archive selection, IAT imports,
Windows ABI adapters/runtime transitions, initializer and unwind handling,
DWARF versus CodeView, and the experimental runtime boundaries. Linked the
existing Windows producer section for commands and full scope. Preserved the
distinction between local Wine evidence and pending native Windows VM results.
Checked the description against pecoff, the Windows generator, binding adapters
and CI configuration; documentation-only changes were checked with
git diff --check and the local heading/link target. No execution test was run
for this documentation change.

## 2026-11-08: Fix native Windows CI developer-shell quoting

Investigated the actual failure reported at
https://github.com/moriyoshi/bao/actions/runs/42470298292/job/128699252660.
The linked amd64 job ran source f9e2cd3d43aa104ebfb821187fb81e150c21f628
on Windows Server 2025 10.0.26100, runner image windows-2025-vs2026
20261103.298.1, with Go 1.26.10 setup successful. It failed in
ci/windows-env.ps1 before Execute CI: PowerShell's native argument binding
re-quoted the already quoted cmd.exe command, which tried to execute
'""C:\Program' instead of the Visual Studio batch file. The ARM64 job
128700963214 in the same run reproduced that setup failure. No native
compilation, linkage or runtime suite passed in these jobs. This supersedes
earlier entries saying the new Windows jobs had not run; the jobs ran, but
their compiler/runtime gates were never reached. Raw downloaded logs remain
.work/windows-ci-failure-job.log and .work/windows-ci-arm64-failure.log.

Replaced the manually constructed cmd.exe/VsDevCmd command with direct
PowerShell invocation of Microsoft's Launch-VsDevShell.ps1 using explicit
-Arch, -HostArch and -SkipAutomaticLocation. This avoids the failing native
command-line quoting boundary and keeps the workspace current directory.
Installation discovery still uses vswhere and the target VC component;
failed discovery or missing Developer PowerShell stops setup. The next step
receives only the existing PATH/INCLUDE/LIB/LIBPATH/toolset/SDK allowlist via
GITHUB_ENV, rather than a full environment dump. Microsoft's recommended
automation entry point and flags are documented at
https://learn.microsoft.com/en-us/visualstudio/ide/reference/command-prompt-powershell?view=vs-2022.

Added ci/windows-env-test.ps1 and run it before actual initialization in both
native Windows CI jobs. The dependency-free fixture invokes the real Bao
setup script against a mock developer-shell script in a Program Files-style
path containing spaces and parentheses. It checks amd64 and ARM64 host/target
arguments, suppression of automatic location changes, propagation of tool
paths/INCLUDE, and exclusion of an unrelated environment variable from the
export. A throwing developer shell must fail without creating GITHUB_ENV.
The explicit InstallationPath parameter is used to isolate this fixture;
normal CI continues to discover the installed Visual Studio toolset.

Local verification used official portable PowerShell 7.6.9 on macOS arm64.
The GitHub release download returned 504 repeatedly, so fetched the identical
asset through its official API endpoint, asset 675638480, and checked SHA-256
a1c7e98ac403da4be5ba75c1c5855af272de7787a91d478c4267466fe58fc1af
before extraction under ignored .work/tools/powershell. Command:

    .work/tools/powershell/pwsh -NoLogo -NoProfile -NonInteractive \
      -File ci/windows-env-test.ps1

All fixture checks passed (log .work/windows-env-regression.log).
actionlint 1.7.12 and git diff --check passed. This is actual PowerShell
fixture execution on macOS, not native Visual Studio initialization or
Windows runtime execution. The fix has not been pushed or rerun on hosted
Windows. README now states that successful native compiler/runtime validation
is pending instead of incorrectly saying no Windows job has run. No Go/native
translator inputs changed, and no unrelated runtime suites were rerun.

## 2026-11-08: README FAQ

Added a shared FAQ and an introductory navigation link. The answers cover
consumer toolchains, native-call transitions, optional purego, dynamic system
libraries, input and platform boundaries, cross-building, Darwin's ELF object
containers, and opt-in signature verification. Each answer links to the detailed
workflow or support profile. Checked these summaries against the current README
and binding generator; no new runtime or platform support is claimed. Preserved
the existing Windows documentation edits and all earlier journal entries.

Verification on Darwin arm64 with Python 3.14.6:
`python3 .work/readme-faq/check.py` passed, checking all 14 FAQ heading links,
the navigation target, balanced code fences, unchanged README content outside
the additions, and the unchanged prior journal prefix.
`git diff --check -- README.md JOURNAL.md` passed. Snapshots and the checker
remain in ignored `.work/readme-faq/`. This documentation-only change ran no
compilation, linkage, native/emulated execution or signing checks.

## 2026-11-08: Bao name origin

Added the first FAQ entry explaining the name's two references: the steamed bun
and Baryon Acoustic Oscillations (BAO), as confirmed by the project author.
Verification on Darwin arm64: `git diff --check -- README.md JOURNAL.md` passed.
This prose-only addition required no compilation, linkage, runtime or signing
checks.

## 2026-11-08: Cosmology parallels in the name FAQ

Expanded the Bao name FAQ with the requested analogies between the lasting
acoustic imprint and build-time translation, a cosmic standard ruler and
section alignment, and photon-baryon coupling and Go/native transitions.
Linked NASA's explanation of the physical phenomenon and described the
comparisons as analogies. Verification on Darwin arm64:
`git diff --check -- README.md JOURNAL.md` passed. No compilation, linkage,
runtime execution or signing checks were needed for this prose-only change.

## 2026-11-08: Preserve provenance bytes in Windows checkouts

Investigated both native Windows failures in run
https://github.com/moriyoshi/bao/actions/runs/42472424422:
amd64 job 128706116458 and ARM64 job 128706116402, source
fb2fcabffb3812af84e1dff050e07d0c58ab4fb7. Both successfully ran the
developer-shell regression fixture and Visual Studio 2026 Developer PowerShell
18.11.3, confirming the preceding quoting fix reached actual initialization.
The amd64 runner was Windows Server 2025 10.0.26100, image
windows-2025-vs2026 20261103.298.1; ARM64 was Windows 11 10.0.26200,
image windows-11-vs2026-arm64 20261101.203.1. Both installed Go 1.26.10
and Rust 1.99.1 and passed pecoff tests, then stopped in bindings at
TestCompilerFixtureProvenance and TestBundledBootstrapSourceProvenance.
Compiler/runtime integration suites were not reached. Raw logs are ignored
.work/windows-ci-128706116458.log and .work/windows-ci-128706116402.log.

Reproduced the failures on macOS arm64 by exporting the existing Git index
with Windows-style line-ending conversion, without modifying the index:

    mkdir -p .work/windows-checkout-before
    git -c core.autocrlf=true checkout-index --all \
      --prefix="$PWD/.work/windows-checkout-before/"

The exported Rust source and bundled bootstrap text had CRLF endings. For
example, infer.rs changed from SHA-256
612c255cb4ff82e0a1344abfe18121b8d96a2377a6537cc9f71fc8aa70dd4aec
to 89e430888a301c8f275a2062951ec1b795cba2d802a39db040e6ea4a6be23177.
Running the two provenance tests in that exported module failed as expected
(negative control, .work/windows-provenance-before.log).

Added .gitattributes with text=auto eol=lf for consistent text checkouts and
an explicit binary rule for *.bin fixtures. Existing provenance hashes and
byte-exact verification remain unchanged. Exported the same index again into
.work/windows-checkout-after with core.autocrlf=true while the new working-tree
attributes were active. Text and binary files in that export matched the
original checkout byte for byte. The existing provenance tests cover the
embedded sources and compiler fixtures without weakening the checks for
Windows or normalizing bytes during hashing.

Verification used the Bazel-downloaded Go 1.26.10 SDK on macOS arm64, with
GOROOT unset and CGO_ENABLED=0 GOTOOLCHAIN=local GOENV=off GOWORK=off.
From the before export, go test -count=1 -run
'^(TestCompilerFixtureProvenance|TestBundledBootstrapSourceProvenance)$'
./bindings failed both expected checks. From the after export,
go test -count=1 ./pecoff ./bindings ./cmd/bao-verify passed all three packages
(.work/windows-provenance-after.log). git diff --check passed. These are
native macOS Go test executions against simulated Windows checkouts; they
do not establish native Windows compiler/runtime success. No hosted workflow
was dispatched and no changes were committed or pushed.

## 2026-11-08: Windows dynamic CRT, compiler TLS, C++ exceptions and weak externals

Implemented the requested Windows amd64/ARM64 lifecycle features. This supersedes
the unsupported CRT/TLS/throw-catch/finalizer/weak-external boundaries recorded in
the earlier experimental Windows entry and README, within the dynamic release
CRT profile described below. The archive is still translated directly into
namespaced COFF .syso inputs for stock Go 1.26.10 with CGO_ENABLED=0: no native
partial linker, runtime extraction or consumer compiler was added.

The original authored pecoff/native/runtime.c is compiled ahead of time for
both architectures and selected into the archive closure only when needed.
It supplies per-image atexit/_onexit/__cxa_atexit lists, MSVC function-local
static epoch guards, native/compiler TLS services and thread-local destructors.
Windows loads the dynamic CRT DLLs normally. Generated Go initializes the
helper, sends TLS process-attach callbacks, runs sorted .CRT$XI C initializers
with a nonzero-return failure check, then runs .CRT$XC C++ constructors.
Shutdown() requires quiescent native callers, runs caller-thread TLS cleanup,
registered exits in reverse registration order, .CRT$XP/.CRT$XT terminators,
TLS process-detach callbacks, and releases its FLS key. It is idempotent.
Go process exit does not invoke this API. Native OS thread exits run FLS cleanup;
a Go caller uses LockOSThread and TLSFinalizeCurrentThread before releasing an
OS thread whose native TLS needs cleanup. Live/destroyed counters are exposed.

MSVC/Clang TLS sections are combined into a sorted, aligned template. Checked
amd64 GS:0x58 and ARM64 X18+0x58 array loads become register/flags-preserving
thunks to private FLS storage; section-relative offsets are applied at build
time, including external references to the helper's TLS guard/epoch symbols.
The private TLS index is zero in this private one-slot array. GCC's Windows
emulated TLS gets separately aligned blocks with the same FLS lifetime.
Template relocations, unrecognized accesses, alignment over 8192 and templates
over 64 MiB are explicit errors. Nonlocal TLS initialization/destruction and
lifecycle callbacks must not throw across the adapter boundary.

Two actual exception-linking issues required changes. Go's special .xdata
placement did not give every compiler RTTI/EH interior symbol an address,
producing an amd64 REL32 overflow to a symbol effectively at zero. Retain
native unwind/RTTI bytes as ordinary private data; canonical amd64 .pdata
still contributes to Go's PE exception directory. This corrects the earlier
claim that native .xdata must also remain canonical. A later independent TLS
address probe changed code layout and exposed a separate GCC amd64 issue:
GCC's cold .pdata contributions preceded its hot function record even though
the linked hot text came first. The linked PE table contained starts 0x1600,
0x1639, 0x1672 followed by 0x1580, and native unwind lookup failed. Earlier
intermediate passes depended on layout and are superseded. Go's loadpe/ld code
does not sort these records. Sort complete amd64 records by text section/value
before emission, preserving record labels and references/addends; reject
malformed or incomplete relocation triplets. A whole-PE assertion then found
another previously masked failure: Go marks native .pdata relocations weak,
and can replace an unused native function address with runtime.unreachableMethod.
An MSVC table contained that Go function at 0x18b60 before native code at 0x1740.
Added an ordinary data array with strong absolute references to every native
function-table relocation target and keep its address live at package init.
This also retains end labels and unwind payloads, and may retain otherwise
unused functions in a selected member. Added a hot/cold/reference-remapping
regression test and a whole-PE assertion in the verifier. The final executable's
entire static exception directory must have ordered starts and valid extents
before any positive example runs; a lucky runtime lookup is no longer sufficient.
ARM64 runtime-function records are merged across objects, sorted by final
function RVA, copied into
native process-heap storage and registered once with RtlAddFunctionTable.
An initial MSVC ARM64 exception probe timed out with per-object tables and
Wine's built-in CRT. The sorted merged table and matching Microsoft runtime
DLLs passed; this does not isolate a single cause for that initial timeout.

Exception imports include MSVC FH3/FH4 and GNU SEH C++ helpers. Fundamental GNU
RTTI objects also come from the matching C++ DLL; a separate int throw/catch
example checks this path in both LLVM-MinGW targets and MinGW GCC. GNU RTTI vtable
pointers are resolved in writable data before native initialization. MSVC's
type_info vftable is a static-library definition, not a vcruntime140 DLL export;
the authored helper provides its deleting-destructor slot. The generated
package depends on installed runtime DLLs, not bundled copies.
-windows-cxx-runtime libc++ selects LLVM-MinGW's libc++.dll/libunwind.dll;
the default GNU mapping uses libstdc++-6.dll/libgcc_s_seh-1.dll. Additional
supported function dependencies can use explicit -windows-import mappings.

COFF weak records implement NOLIBRARY, LIBRARY and ALIAS policies, with ordinary
strong-reference closure considered before fallback resolution. Strong selected
definitions win. /ALTERNATENAME fallbacks, /INCLUDE roots, release dynamic CRT
/DEFAULTLIB requests and matching /FAILIFMISMATCH records are interpreted.
Invalid/cyclic weak records and anti-dependency records remain errors. Missing
GNU weak function addresses stay null: absolute pointer relocations retain zero,
checked address materialization preserves flags, and unreachable direct calls
use a private null tail jump to avoid an out-of-range PC-relative link to zero.
An unused absolute-zero fallback is also removed when a strong definition wins.
Real weak_optional.c/weak_override.c controls return 42 without the definition
and 7 with a selected strong definition. MSVC C tentative/common definitions
coalesce to maximum size while initialized strong definitions take precedence.
BSS-only emitted objects are padded before the symbol table because Go's
debug/pe probes a 96-byte DOS header even for COFF.

Added independent lifecycle.c/lifecycle.cpp/exceptions.cpp/weak.c examples and
a signature manifest. They check C initialization before C++ construction,
CRT malloc/free, typed throw/catch/rethrow through two RAII frames, initialized
and zero TLS, a Go-side check of the actual 128-byte-aligned native TLS address,
eight OS-created threads, nine C++ TLS destructors, zero remaining TLS blocks,
TLS process/thread notifications, and global/function-local static finalization.
Shutdown runs the local static destructor, two explicit exits, global destructor,
pre-terminator and terminator exactly once in order 6/2/1/3/4/5. Negative controls
omit C initialization, native unwind registration/directory participation,
caller TLS finalization and shutdown; each links and then fails its intended
state check without a PASS marker. The alignment probe originally used the
reserved TLS binding prefix; renamed its Go binding AlignedAddress. Those
failed intermediate attempts are not counted as successful verification.

The full Windows verifier invokes these checks after the existing scalar ABI,
constructor/unwind, runtime-registration and Cargo no_std gates. It also checks
the real GNU null-weak and strong-override examples. Native CI continues to use
Windows VMs, never Wine. ci/windows-llvm.ps1 installs LLVM-MinGW release 20261104
with pinned release SHA-256 digests (x64 ZIP
552191b5754c49a5a20723276a6fc56541ea1922c4c50b7b669022333fc1b40f,
ARM64 ZIP 7d7f8387a8706639b0b47a629d6e23f8b3ef9acce67e9832b8cd4c5bb2816eab).
GNU Clang uses that matched compiler/runtime set; installed VC++/clang-cl and
actual MinGW-w64 GCC remain separate gates. No automated MSVC downloader or
MSVC redistribution was added to Bao.

Final local verification used macOS arm64, Go 1.26.10, Rust 1.99.1, MSVC
19.44.35229 for x64 and ARM64, Apple clang 21.0.0 for clang-cl, LLVM-MinGW
20261104 clang 23.1.5 for GNU Clang, and MinGW GCC/G++ 16.1.0 on amd64.
All seven compiler legs compiled fresh native inputs, linked fresh consumers
with CGO_ENABLED=0 and invalid CC/CXX paths, and executed at GOMAXPROCS=1 and 4.
The GNU legs additionally executed missing-weak/strong-override controls and
fundamental int exceptions with DLL-provided RTTI.
Logs and compact results for MSVC/clang-cl are
.work/results/windows-lifecycle-arm64-<driver>-v4 and
.work/results/windows-lifecycle-amd64-<driver>-v6; the GNU compiler legs with
the additional fundamental-type exception check are
.work/results/windows-lifecycle-<arch>-<driver>-v7;
all are labeled CHECKED_WITH_LIMITATIONS and Wine, not native Windows execution.
amd64 execution used Wine 11.21 on macOS/Rosetta. ARM64 used Wine
10.0~repack-6 in the task-owned arm64 Docker container, based on GCC image
sha256:2bafb163aaa91eef7856f17ff0abf69144ebe3218a4eea75c043bb3043b9ecfa
and Debian snapshot 20261108T000000Z. The image was restored after external
pruning and retained by an owned container during testing.

The GNU toolchain was downloaded from the official LLVM-MinGW release API and
its macOS universal tar.xz SHA-256 verified as
66cbd5178c4a71b0d473e68ede172f8eb7d15d023e67f39201d0a69e21f6bf3c.
For local MSVC exception execution, downloaded the matching official 14.44
runtime VSIX payloads and checked their catalog hashes: ARM64
fc8f37250188509818258582758a3b704810c77b6d25845486d583ea99d9aa1f,
x64 4aaf54db0bfc9435f7c3660e1a00237a4b556042bfeea64bde44c2e0194e6ee5.
They unpack to VC/Redist/MSVC/14.44.35112. Their DLL SHA-256 values are recorded
in each result.json. The prior installer catalog/channel hash-chain limitation
still applies: these checks are payload integrity against that HTTPS catalog,
not a new validated installer trust chain or Authenticode verification.
Original packages, licenses and notices remain under ignored .work/msvc.

Reproduction for the real MSVC amd64 leg (use the corresponding ARM64 runtime
directory, MSVC_ARCH=arm64, target and Wine runner for the ARM64 leg):

    export MSVC_TOOLS="$PWD/.work/msvc/root/VC/Tools/MSVC/14.44.35207"
    export MSVC_ARCH=x64
    export WINE="$PWD/.work/tools/wine/Wine Devel.app/Contents/Resources/wine/bin/wine"
    export WINEPREFIX="$PWD/.work/windows-wine/prefix-amd64"
    export WINEDLLOVERRIDES='vcruntime140=n,b;vcruntime140_1=n,b;winedbg.exe=d'
    bazel run //:verify -- -suite windows -target windows/amd64 \
      -windows-driver msvc -windows-cc "$PWD/ci/msvc-wine.sh" \
      -windows-cxx "$PWD/ci/msvc-wine.sh" -windows-ar x86_64-w64-mingw32-ar \
      -windows-dll-dir "$PWD/.work/msvc/root/VC/Redist/MSVC/14.44.35112/x64/Microsoft.VC143.CRT" \
      -windows-runner "$PWD/.work/windows-wine/run-amd64.sh"

For GNU Clang use -windows-driver clang, the LLVM-MinGW target-prefixed clang/
clang++ executables and that target's bin directory for -windows-dll-dir. For
MinGW GCC use -windows-driver mingw and its matching C++/unwind/pthread DLLs.
ci/windows-env.ps1 still selects the native installed VC environment in CI.
The vctip workaround remains limited to the disposable local compiler copy.

Native helper regeneration is available through bao-native -target windows/amd64
or windows/arm64. Both are built with clang -O2 -ffreestanding -fno-builtin
-fno-stack-protector -funwind-tables; ARM64 also uses -mno-outline-atomics.
Manifests retain compiler/version/flags and SHA-256 for source and object.
Source runtime.c SHA-256 is
d729b34769f5c286ec55c8f19db36a4de5b5ba5be69c1b79ffdd66569e6d31d3;
amd64 runtime.bin is 62f3cefa0821cc2ef5c9b74ded7e7cff00bafea815c09969aaa838175fe7596e;
ARM64 runtime.bin is b0128da7b19013a54c6fb713043d2cf6f203310e73856afe4117d0e152c4d1a5.
Generated lifecycle packages retain Bao's Apache-2.0 license and native-helper
notice. No third-party DLL is included in those packages. Documentation now
describes lifecycle APIs, compiler flags, runtime selection and the boundaries.

Retranslating all seven final native archives with the current CLI produced
byte-identical Go, assembly and COFF artifacts, including ARM64 after the
amd64-only sorting correction and the reserved Shutdown binding-name check.
The license/notice files were checked against the source license. This is an
artifact identity check, not reuse of an executable for changed native inputs.

All 11 Bazel unit targets passed with --nocache_test_results, including helper
provenance, TLS access validation, common storage, weak policies, null pointers,
cycles/indices and directive rejection. go vet ./..., actionlint 1.7.12,
PowerShell 7.6.9 parsing of windows-llvm.ps1, shell syntax and git diff --check
passed. The CLI cross-compiled for both Windows architectures; this is compilation,
not execution of those Windows CLI binaries. Native Windows VM runs, signing
and release publication were not performed. Static/debug CRTs, full Rust std,
duplicate selected COMDAT definitions, bigobj, ARM64EC, Windows/386 and arbitrary
unrecognized TLS models remain outside the profile. No changes were committed
or pushed. The earlier unrelated line-ending fix and existing user edits were
preserved. The task-owned Wine container/server were cleaned up after verification.

## 2026-11-08: Windows COFF COMDAT selection and multi-file C++ verification

Implemented COMDAT selection for the requested Windows amd64/ARM64 profile.
This supersedes the duplicate-selected-COMDAT exclusion in the preceding
Windows dynamic CRT entry. Previously Bao cleared COMDAT flags after archive
selection and rejected duplicate external definitions, so the earlier seven
compiler legs did not establish support for shared inline/template definitions.

pecoff/comdat.go reads section-definition auxiliary records before TLS layout,
SEH merging or symbol renaming. NODUPLICATES rejects extracted duplicates;
ANY retains the first selected contribution in archive order; SAME_SIZE checks
sizes; EXACT_MATCH compares bytes and relocation identities independently of
symbol-table indices; LARGEST chooses the largest selected contribution.
NEWEST uses the greatest ordinary COFF header timestamp, which the parser and
encoder now preserve. Equal-size/time choices retain archive order. These
policy choices have synthetic COFF unit coverage; the compiler examples cover
the policies their actual objects emit, rather than claiming native examples
for every policy. The format reference is Microsoft's
[PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#comdat-sections-object-only).

ASSOCIATIVE chains are validated for missing/non-COMDAT parents and cycles,
including chains subsequently discarded. Children follow their parent's
selection before .pdata/.xdata aggregation, CRT table collection or TLS layout.
References into discarded definitions become undefined externals naming the
winning definition. Referenced local/section symbols use winning-section
anchors with their symbol offsets retained. Associated metadata counterparts
are matched by parent, full section name and sibling occurrence; absent or
out-of-range counterparts are rejected when needed. Redirected section symbols
lose their section auxiliary records, and compaction remaps relocations and
weak-alias TagIndex references. Ordinary duplicate definitions and conflicting
COMDAT policies still fail. EXACT_MATCH conservatively rejects cross-contribution
local targets whose equivalence cannot be proved.

Archive extraction repeats from pristine object copies when the selected member
set grows. COMDAT selection is reapplied before scanning newly extracted members,
and DLL-import validation is deferred until extraction stabilizes. Discarded
copies therefore do not contribute their own unresolved imports, TLS storage or
associated initializers/unwind records. Already extracted archive members remain
selected, as in the existing archive closure. Selection considers extracted
members, not every unused alternative in the archive. Local MSVC leaders retain
object scope. GNU named .pdata$/ .xdata$ contributions without external leaders
use their full names; GCC private debug-frame COMDATs do not participate in
runtime definition selection. Mixed compiler/ABI archives were not verified.

Real MSVC ARM64 input exposed repeated function-scoped $LN labels within one
object. Go scopes locals by object, so these previously collapsed to one address
and generated duplicate function-table entries. Bao now gives local symbols,
including class-6 labels, identities based on object and symbol indices while
preserving section-symbol treatment. This corrected the real ARM64 function
table failure; the generated duplicate-entry guard was retained. Unit coverage
also checks local-label identity, nested associations, discarded unknown imports,
unextracted NODUPLICATES alternatives, exact-match relocation differences,
weak-alias compaction, and removal of losing unwind records before aggregation.

The maintained examples/windows_runtime/comdat.h, comdat_a.cpp and comdat_b.cpp
emit real duplicate inline functions, a template instantiation, vtables, inline
static objects/guards and compiler TLS. cmd/bao-verify/windowscomdat.go requires
actual duplicate external COMDAT symbols in both compiler outputs, then builds
and executes a fresh CGO_ENABLED=0 typed Go consumer. It checks five shared
addresses across translation units, two initializations, two RAII drops, typed
throw/catch, native unwind lookup and two finalizations after idempotent Shutdown.
The state is 202 before shutdown and 222 afterward. Positives run at
GOMAXPROCS=1 and 4. A separately built negative removes native unwind metadata
and must produce the expected COMDAT failure without a PASS marker. Lookup runs
before throwing so the negative does not attempt an invalid unwind. An early
negative that did throw without metadata hung under ARM64 Wine and was stopped;
that interrupted attempt is not a passing negative-control result.

This check is called by the existing Windows suite after its Rust and lifecycle
gates, so the native Windows CI jobs automatically require it for every compiler
leg. No CI workflow was dispatched here. The final seven full-suite executions
used newly compiled native objects and newly linked consumers, with invalid
consumer CC/CXX paths, and left input archive hashes unchanged. Each also passed
the earlier scalar ABI/scheduler, Cargo no_std, constructor, lifecycle, weak and
exception checks applicable to its driver. The amd64 harness checked the linked
PE exception-directory ordering. Results are CHECKED_WITH_LIMITATIONS, not native
Windows passes:

| Target | Producer | Duplicate external COMDAT symbols | Final COMDAT archive SHA-256 |
| --- | --- | ---: | --- |
| windows/amd64 | MSVC 19.44.35229 | 18 | 933b1fb09d50a2f59cca5703a907bb4e81fc8c948bf0301b11113235ad56e4f8 |
| windows/arm64 | MSVC 19.44.35229 | 18 | 81f0d1dbee2470fbc18f82f7112bdadf172bed15a13bef05d351bab659466814 |
| windows/amd64 | Apple clang-cl 21.0.0 | 15 | 93d7617190073d7f2f5a476ceb6b79b5c37a541affb0a25833f08b989bd20191 |
| windows/arm64 | Apple clang-cl 21.0.0 | 15 | 8782e50f2115c9466783e82d300a9a4c98dfc8ec4c6aacb012e492835766f2c7 |
| windows/amd64 | LLVM-MinGW Clang 23.1.5 | 15 | 20278e11392a51e7b1d9c1d769d8410392e0a138a05dcd5895182f049c2fbf00 |
| windows/arm64 | LLVM-MinGW Clang 23.1.5 | 15 | fe90431bda1aa2d1420749d7309a400e9fee136b1fc8c86f500f88b72e494e87 |
| windows/amd64 | MinGW-w64 GCC 16.1.0 | 16 | 3407c8c9de27d230792e190c0685cca484db2ac8c81c843bcf379308999d4af2 |

Execution environment was this macOS/arm64 host: amd64 used Wine 11.21 with
Rosetta; ARM64 used Wine 10.0 (Debian 10.0~repack-6) in the existing pinned
Linux arm64 Docker image. These are Windows-compatible Wine executions, not
native Windows VM runs. The MSVC ABI legs loaded Microsoft's matching native
runtime DLLs using WINEDLLOVERRIDES=vcruntime140=n,b;vcruntime140_1=n,b.
GNU Clang used the pinned LLVM-MinGW 20261104 kit and its matching libc++/unwind
DLLs; GCC used its matching libstdc++/libgcc/pthread DLLs. Compiler/runtime
license and signing limitations remain as recorded in the preceding entry.

Reproduction uses Go 1.26.10, Rust 1.99.1, Bazel 8.4.2 and the producer/runner
paths documented in the preceding Windows entry. MSVC C++ flags are /O2 /Z7
/MD /GS- /std:c++20 /EHsc /GR-, plus /forceInterlockedFunctions- for ARM64.
clang-cl adds its MSVC target, /clang:-ffreestanding and /clang:-funwind-tables.
GNU flags are -O2 -g -ffreestanding -funwind-tables -fno-omit-frame-pointer
-std=c++20 with the matching target compiler. Representative harness invocation:

```sh
bao-verify -root "$PWD" -bao /absolute/path/to/bao -go /path/to/go1.26.10 \
  -suite windows -target windows/arm64 -windows-driver clang \
  -windows-cc /path/to/aarch64-w64-mingw32-clang \
  -windows-cxx /path/to/aarch64-w64-mingw32-clang++ -windows-ar llvm-ar \
  -windows-dll-dir /path/to/llvm-mingw/aarch64-w64-mingw32/bin \
  -windows-runner /path/to/arm64-wine-wrapper \
  -evidence .work/results/windows-comdat-arm64-clang
bazel test --lockfile_mode=error --nocache_test_results //:tests
CGO_ENABLED=0 go vet ./...
```

Final compact results are .work/results/windows-comdat-<arch>-<driver>-v6/;
raw root logs are .work/comdat/<arch>-<driver>-v6.log, each naming its fresh
.work/verify-windows-* artifact directory. All 11 Bazel targets passed without
cached test results, go vet and git diff --check passed, and the CLI compiled
for Windows amd64 and ARM64. Those Windows CLI binaries were not executed.

An additional source pattern is outside this verification claim: returning a
native template-call result directly from an ARM64 clang-cl catch block. Apple
Clang 21 and LLVM-MinGW Clang 23 targeting the MSVC ABI both emitted an apparent
result clobber in the original, untranslated object: after bl template, adrp/add
overwrite x0 with the catch continuation, then stur x0 writes that address into
the parent frame's return slot. The translated consumer returned that image
address while identity and RAII counts passed. The instruction sequence is
evidence for a producer-code issue; a separately linked native PE control was
not run, so this is not a complete upstream compiler diagnosis. Raw probes are
.work/comdat/clang-arm-a.dis and 23-arm-msvc-a.dis. The maintained example calls
the template inside the throwing frame and returns the captured scalar from
catch, preserving template, RAII and exception coverage. No machine-code repair
or broad compiler-support claim was added for the failing pattern.

README now documents COMDAT behavior, the two-file example and its CI gate.
Full Rust std, static/debug CRTs, bigobj, ARM64EC, Windows/386, arbitrary TLS
forms and exception propagation across Go frames retain their earlier boundaries.
Native Windows execution, signing and release publication remain pending.
No changes were committed or pushed; unrelated edits and the README editor swap
file were preserved. Scratch probes and downloaded tools remain under .work/.
The task-owned ARM64 Wine container was removed, and no task Wine/keepalive or
verification processes remained after cleanup.

## 2026-11-09: Linux static language runtimes, explicit fini arrays and full-static boundaries

Implemented and checked bundling GNU C++ and Rust language-runtime code for
Linux arm64, amd64, loong64 and ppc64le while retaining dynamic OS libraries.
This supersedes the earlier Linux exclusions for ELF fini arrays and the
unverified Linux amd64 Rust std statement. It does not establish fully static
Bao executables, musl support, arbitrary static archive compatibility or physical
hardware execution on the three emulated targets.

The common producer accepts repeated -link-archive and -link-notice options.
For ELF it whole-loads the primary archive and searches dependency archives in
an ld --start-group/--end-group. C++ checks select libstdc++.a, libgcc_eh.a and
libgcc.a; Rust staticlibs already contain std and add the latter two archives.
Primary input, dependency archives and notice bytes are captured before linking.
The linker/generator use private snapshots, while bao-build.json records the
original paths and captured SHA-256 values. Explicit notices are copied without
rewriting. This preserves provenance when caller-owned files change during a
producer invocation; it is not an assertion that producer tools or native code
are untrusted-code sandboxes.

Linux translation now identifies a bundled STT_FUNC __register_frame and emits
an address accessor for local FDE registration instead of requiring a shared
libgcc_s registration function. Strong unresolved imports can still require
shared libraries; final dependency audits determine the actual result. Retained
SHT_FINI_ARRAY sections become addressable native data, with descending numeric
priority, reverse table order and reverse entry order. FinalizeRuntime() runs
these tables through sync.Once. Stop native work, finish explicit library C++
shutdown and caller TLS cleanup before calling it. It is not automatic process
exit, a replacement for library shutdown, or an image-unloading API. ELF init/fini
priority suffixes are checked in 0..65535. A real two-entry AMD64 fini table used
16-byte section alignment, so the former artificial maximum of eight was removed;
normal section alignment validation and preservation remain in force.

Partial linking coalesces GNU unique C++ objects before translation. Defined
STB_GNU_UNIQUE objects become ordinary global objects with the same identity
inside the supported single native image; undefined or non-object unique forms
are rejected. This does not provide DSO interposition or cross-image uniqueness.
PPC64 TOC16_DS uses the relocation already supported by stock Go. The sysroot
catalog additionally reads target loader exports: the static GCC PPC CPU helper
uses the public GLIBC_2.23 export __parse_hwcap_and_convert_at_platform from
ld64.so.2. No private substitute was introduced.

Undefined weak imports no longer select a shared provider by themselves. A weak
reference binds to a catalog provider only when a strong import or required
unwind registration already needs that provider; otherwise its address remains
NULL. This matters for the weak __cxa_pure_virtual reference in libstdc++.a,
which previously reintroduced the shared C++ runtime despite static archive
selection. Unit checks cover weak-only and strongly required provider behavior
through all four architecture binders, plus GNU unique identity and rejection.
Linux native helper source/blobs/manifests were unchanged by this work.

The maintained cmd/bao-verify/staticlinux.go suite compiles independent
examples/cpp_linux/runtime.cpp and examples/linux_runtime/src/lib.rs inputs.
A new testdata/linux_static_fini.cpp observes fini priority and reverse entry
order as 321; repeated FinalizeRuntime calls must leave 321 unchanged. The C++
fixture checks caught exceptions and two RAII drops, eight native workers, nine
TLS destructors, 128-byte alignment, late pthread cleanup, constructors, imported
data and three explicit static destructors. The Rust fixture checks the
corresponding std panic/unwind, thread, TLS and native import behavior. Its libc
environ foreign static now uses link_name="__environ", matching glibc's GLOBAL
alias already used by the C++ fixture. The ordinary LoongArch BFD control
initially returned 4 for weak environ ABS64/GOT address inequality, including
with -fPIC/-pie; the global alias fixed that native control without instruction
patching. Final Rust source SHA-256 is
8032e810ce3f2ca6dc1055261666ad47c443896bda544b341a221e84ff5b743b.

Verification used stock Go 1.26.10, Rust 1.99.1 (58cf8f9c3), Debian GCC
14.2.0-19, target GCC 14.2.0-19cross1, GNU Binutils 2.44 and glibc 2.41.
The extended testdata/toolchains/linux-cross.Dockerfile pins its Rust ARM64 base,
dated Debian snapshot and package versions, and now includes x86_64 cross GCC/G++
and the x86_64 Rust std target alongside LoongArch and PPC. The local image was
bao-static-linux:all, digest
sha256:b944f3b104b0dc573035bdbe610c07aa5671da4a76934b8a8b9d5d046809dd11.
Execution used the macOS/arm64 host's Colima Linux/aarch64 daemon. Linux arm64 ran
natively in Docker. amd64, loong64 and ppc64le used explicit QEMU user-mode
10.0.13 with their matching /usr/<triple> sysroots. These are emulated execution
passes, not physical target hardware passes. All consumers ran in read-only,
network-disabled containers with unavailable CC/CXX/RUSTC paths.

All four targets passed fresh C++ and Rust consumers in both runtime-registration
(PureGo v0.11.3) and typed assembly-binding modes (standard library only), for
16 separately built consumers. Each ran at GOMAXPROCS=1 and 4. Original native
archives remained unchanged. Actual final DT_NEEDED entries were libc.so.6,
libpthread.so.0 and libdl.so.2; none required libstdc++, libgcc_s, libc++ or
libunwind. PT_INTERP remained present. Omitting caller TLS cleanup or fini
execution produced the expected lifecycle failure in each consumer. Removing
FDE registration left the native bytes unchanged and still linked, but native
throw/panic aborted instead of passing. Fifteen GCC/Rust copyright and license
files, including Rust's library copyright inventory and all bundled license
texts, were retained byte-identically. Their inclusion does not replace the
distributor's obligation to identify and carry all applicable input notices.

Each target also built and executed ordinary compiler-produced C++ and Rust
controls in two modes: static language runtimes with dynamic OS libraries, and
-static executables with no DT_NEEDED or PT_INTERP. testdata/linux_rust_control.c
uses a real pthread so native CRT/glibc own its thread teardown. The fully static
Rust control explicitly roots __cxa_thread_atexit_impl using
-Wl,-u,__cxa_thread_atexit_impl. Without this root, Rust std's weak probe did not
extract glibc's static implementation, fell back to pthread-key TLS cleanup and
violated the fixture's required Cxa-before-pthread ordering (the initial ARM64
control returned 9). Extracting the actual glibc implementation restored the
required ordering and all four controls passed. Static Rust linkage emitted
glibc warnings about getaddrinfo/getpwuid_r needing matching shared libraries
when used. These fixtures do not exercise DNS/NSS/plugin behavior and do not
establish universal runtime hermeticity. Compiler controls are separate from
Bao support.

Bao fully static linkage remains unsupported by the present Go/native
bootstrap, which uses dynamic glibc, pthreads and symbol lookup. With cgo
disabled, -ldflags='-linkmode=external -extldflags=-static' failed exactly with
"-linkmode=external requires external (cgo) linking, but cgo is not enabled".
The internal-link counterpart succeeded but retained PT_INTERP and OS DT_NEEDED
entries, as independently audited. Passing -extldflags=-static to the internal
linker is not a fully static Bao pass. These probes and their resulting files
are retained separately from successful static-language-runtime consumers.

Final execution records are .work/static-linux/result-<arch>-v4/ for arm64,
amd64, loong64 and ppc64le. Their artifacts.json files name the fresh
.work/static-linux/verify-static-* directories; raw root logs are
.work/static-linux/suite-<arch>-v4.log. The host CLI snapshot bao-v3 SHA-256 was
f692aeeca18c228059cd5dbef7bae0460f4710029da7bdc9fc12f42cb94cf260.
The actually used Linux producer, rebuilt with the pinned SDK, was
71bcd0cee639e15fe51861fd92a69000ed7e7643d80ead586df146c261b24025.
After the passes, only verification ordering changed to run Rust controls and
consumers before C++, preserving the requested Rust gate. Linux ARM CI now runs
all four static target suites after the earlier Rust/C++ gates. No remote CI
workflow or Linux signing check was performed for these static artifacts.

The later common -require-static-runtime flag rejects recognized shared
C++/Rust/unwind runtime names in the native manifest and generated Go dynamic
import directives, including implicit libgcc_s registration imports. Successful
bao-build.json provenance records require_static_runtime=true. This is an audit
of declared known library imports, not arbitrary dlopen/LoadLibrary behavior or
a claim of fully static OS linkage. New portable regressions use real COFF
translation to establish ordinary shared C++/unwind imports, then require strict
build rejection without output/staging or source mutation. A separate empty
manifest plus generated blank libgcc_s.so.1 import must also reject; libc.so.6
remains allowed. A strict runtime-free CLI build records the positive contract.

The current producer retranslates all 16 Linux packages with the strict flag.
Every generated Go, assembly and .syso file is byte-identical to the already
executed v4 packages: 58 files per architecture, 232 total. The strict Linux
producer SHA-256 is
b3006b46324cc147d02ec3d717c599dc8b964805b30cae3010603c82a167bfd9.
Proofs are .work/static-linux/identity-strict-<arch>.json, raw logs are
identity-strict-<arch>-<language>-<mode>.log, and the exact reconstruction from
saved bao-build.json files is .work/static-linux/check-strict-identity.py.
Consumer execution was not repeated for these byte-identical artifacts. Earlier
post-snapshot identity proofs are identity-<arch>.json in the same directory.

Additional unit tests cover repeated dependency order/multiplicity, ELF group
search, Darwin primary force-load/dependency search, mismatched/mixed/raw or
malformed dependencies, notice bytes/digests, rollback and reserved binding
names. A Unix FIFO notice provides a deterministic snapshot barrier: replacing
the original primary, dependency and notice during production still yields the
original digests and byte-identical Go/assembly/native output. No compiler/SDK
is needed for these producer regressions. go test ./cmd/bao ./toolchain
./linuxelf and relevant bindings/verification tests, go vet for the changed
packages, shell syntax and git diff --check passed with Go 1.26.10.

Reproduction from the source checkout on an ARM64 Docker daemon, with the pinned
Go SDK selected by Bazel:

```sh
docker build --platform linux/arm64 \
  -f testdata/toolchains/linux-cross.Dockerfile -t bao-static-linux:all .
for arch in arm64 amd64 loong64 ppc64le; do
  bazel run //:verify -- -suite static -target "linux/$arch" \
    -image bao-static-linux:all -evidence ".work/static-linux/recheck-$arch"
done
bazel test //cmd/bao:bao_test //toolchain:toolchain_test //linuxelf:linuxelf_test
```

The Docker build prepares compiler dependencies with network access; verification
uses the prepared image without network. The reproduction commands are maintained
entry points, not a claim that a new Bazel or remote CI run occurred for this
journal append. Remaining limits include one native runtime image, glibc ABI
compatibility, supported TLS/relocation forms, no image unloading/interposition,
no exception propagation through Go frames and unverified target hardware outside
ARM64. No source or native library is extracted at consumer runtime. No changes
were committed or staged by this task, and unrelated user/platform edits remain
preserved.

## 2026-11-09: Static language runtimes on Darwin and Windows, CI gates and full-static limits

The static-linking request covers both bundled language runtimes with dynamic
OS libraries and executables without shared-library dependencies. The preceding
Linux entry records the four ELF targets. This entry adds Darwin arm64/amd64
and Windows arm64/amd64 verification. Static language-runtime profiles now have
execution evidence on all eight targets. Fully static Bao executables remain
unsupported on all targets: native compiler full-static Linux controls are not
Bao passes. This supersedes broad earlier statements that bundling language
runtimes was unverified, within the exact compiler profiles below. It does not
supersede the C++ exception limitation on Darwin, the Windows Rust std limit,
or the static/debug Microsoft CRT limits.

The common build frontend provides repeatable -link-archive and -link-notice,
and -require-static-runtime. Before linking it captures the primary input,
every dependency archive and every notice. Linkers consume private snapshots;
bao-build.json records original paths and hashes of the bytes actually used.
Notice copies retain their original bytes. Linux uses grouped archive searches;
Darwin force-loads the primary archive and ordinarily searches dependencies;
Windows combines COFF members and selects their referenced closure in Bao.
Single-input COFF combination preserves its original bytes and namespace hash.
No new consumer compiler, runtime extraction or executable-memory loader is used.
The strict flag checks manifest imports plus generated dynamic-import directives,
including an otherwise implicit shared unwind registration dependency. It rejects
known language-runtime library names before publication and rolls back staging.
It does not authenticate inputs, infer license obligations or detect arbitrary
native dynamic loading, renamed libraries or transitive system dependencies.
Portable tests cover shared C++ and unwind rejection, allowed OS libraries,
notice/hash preservation, mutation after snapshot, target/archive mismatch,
argument ordering and failed-output rollback.

Darwin translation recognizes a bundled __register_frame definition and binds
FDE registration to it rather than importing libSystem's registration function.
The new ci/darwin-static-runtime.sh builds static LLVM libc++, libc++abi and
libunwind from llvmorg-23.1.5, exact commit
392dfff97d29b59d77e5cac6d4b6ef2585fe7117. C/C++ frames retain frame pointers;
libc++ and libc++abi C++ exceptions are disabled, and their static libraries
include the ABI/unwinder rather than requiring libc++.dylib. The script verifies
the source revision, installs all three component notices and records target,
SDK version and the no-C++-exceptions setting. This is a producer/CI tool using
Git, CMake and Make, separate from Bao's Go/Bazel build and generated consumers.
Both script invocations completed locally, reusing a revision-checked source
checkout and per-architecture build directories. Both resulting installations
then passed the maintained suite; earlier manually built archives were not
substituted as evidence for these changed builder outputs.

Darwin verification used macOS 26.5.2 arm64, SDK 26.5, Apple Clang 21.0.0
(clang-2100.1.1.101), Go 1.26.10 and Rust 1.99.1
(58cf8f9c3 2026-10-13). arm64 execution was native; amd64 used Rosetta 2.
Fresh Rust std/catch-unwind inputs gate the C++ fixture. The latter allocates
strings/vectors in global and function-local statics, runs eight pthread workers,
uses 128-byte-aligned TLS with nine destructor calls and checks two explicit
static finalizers with idempotent shutdown. These static Darwin consumers use
generated typed bindings and the standard library only. Both GOMAXPROCS=1 and 4
passed, as did ad-hoc hardened-runtime signing, strict signature verification
and signed execution. Missing caller TLS cleanup fails both languages; omitted
FDE registration links but aborts Rust unwinding; omitted C++ finalizer calls
fail the separate finalized-state observation. The no-FDE mutation initially
left a typed local unused and failed compilation, so it was corrected before
accepting the linked-and-executed negative result. That failed compilation is
not the unwind negative pass.

Each Darwin C++ package preserves all three LLVM notices. Each Rust package
also preserves Rust COPYRIGHT-library.html and every installed Rust library
license, for 16 notices total. The suite compares every copied notice hash.
Final Mach-O imports are libSystem/libresolv, with CoreFoundation additionally
for Rust; no libc++/unwinder dylib remains. A C++-exceptions-enabled initial
runtime probe still failed on the known compact personality/LSDA boundary;
no claim of static C++ throw/catch on macOS is made. The supported macOS SDK
and stock Go require dynamic OS libraries, so a no-shared-library Darwin Bao
executable is not available.

Final builder verification records are
.work/results/static-darwin-{arm64,amd64}-builder/, with raw
.work/static-darwin/verify-<arch>-builder.log and builder-<arch>.log.
The resulting runtime archive hashes were:

| Target | libc++.a SHA-256 | libunwind.a SHA-256 |
| --- | --- | --- |
| Darwin arm64 | d134be25df24c1c4ab145c4d8189e88ca932bf491f1747d2053460bbc3c3e474 | 0201ce4056556076872e8bdfc329ec561a3e9ac60b76aefa3d4ae3a8ccb6978f |
| Darwin amd64 | 564742a6d3c5d387cd0f13b14245de02d06e1648b7d72ae6251e6a11920323e5 | 25f393068b457175ea8437fee1c7257a43ac14582349010081d87bddd4026f9f |

Windows static LLVM-MinGW inputs required concrete archive and backend changes:

- The reusable ar parser accepts Microsoft's NUL-terminated long names and
  retains /<ECSYMBOLS>/ as opaque symbol-table bookkeeping. Its generic view
  preserves all ordinary object members, including alternate ABI objects.
- The internal COFF dependency view selects the requested ordinary AMD64/ARM64
  plane only when the archive has an explicit EC index. ARM64EC/ARM64X objects
  remain unsupported. Ordinary mixed-architecture archives still fail a target
  mismatch. Actual ARM64 libmingwex contains both ordinary architectures in
  addition to alternate ABI objects; merely dropping ARM64EC was insufficient.
- Mixed CRT import libraries contain real compatibility wrappers as well as
  import declarations. The dependency view retains native wrappers and skips
  short import records and .idata thunks. An import-only dependency has no native
  members and fails; no new DLL authority is inferred. Direct .idata native
  inputs are rejected instead of treating zero import cells as implementations.
- Archive weak aliases with same-member native fallback implementations become
  providers, with real strong definitions preferred. Separate local IAT cells
  satisfy __imp_Foo when a native Foo exists; extracting one cell does not pull
  unrelated providers. Authored lifecycle-helper fallbacks stay local when an
  explicitly linked native definition already exists.
- GNU .ctors.N/.dtors.N priorities are checked and ordered; .ctors arrays run in
  reverse. Standard OS exports needed by the static libraries are catalogued,
  including canonical UCRT export aliases for __msvcrt_assert and fileno.
- Stock Go does not consume ARM64 REL32. LLVM's same-object read-only constant
  pointer tables are resolved at build time by retaining their .rdata sections
  together, preserving alignment, other relocations and symbol offsets. Code,
  writable, external-target, overlapping, overflowing and out-of-bounds forms
  are rejected. Microsoft's PE format and LLVM COFF relocation implementation
  specify target minus the address following the four-byte relocation.
- MinGW winpthreads has a private, unread _include_tls_used pointer whose sole
  purpose is requesting a PE TLS directory. Only that const linker anchor is
  lowered; actual reads of _tls_used remain unsupported. The existing private
  FLS implementation still delivers retained CRT callbacks. This does not add
  general loader-managed PE TLS directories or arbitrary TLS loader semantics.

Windows static verification used LLVM-MinGW 20261104 UCRT, Clang 23.1.5 at the
same LLVM commit, and Rust 1.99.1 no_std as the preceding execution gate. C++
links libc++.a, libc++abi.a, libunwind.a, libmingwex.a, target compiler builtins
and libucrt.a compatibility wrappers. The current GCC 16.1.0 / MinGW-w64 14
Homebrew producer also targets UCRT, as confirmed by its _UCRT preprocessing
macro; it must not be assumed to use legacy MSVCRT. The -windows-crt ucrt|msvcrt
option selects matching system CRT import names and defaults to UCRT. It does
not implement a static CRT startup routine.

Both LLVM static legs freshly compiled, translated, linked and ran lifecycle,
COMDAT and fundamental int throw/catch consumers. The checks include CRT C/C++
startup, real allocation, typed catch/rethrow with RAII, eight native workers,
nine TLS destructors, weak fallback/override, explicit idempotent shutdown and
static exit order 621345. COMDAT checks include duplicate inline/template/vtable
identity, TLS identity, associated unwind lookup and static finalizers.
GOMAXPROCS=1 and 4 passed. Separate C initialization, caller TLS cleanup, static
shutdown and native unwind-metadata negatives failed as intended. Eleven
package manifests per target (including negative copies) and final PE imports
were audited: kernel32/ucrtbase remain, without shared C++/ABI/unwinder DLLs.
The Wine environment explicitly disabled libc++, libunwind, libstdc++-6,
libgcc_s_seh-1, vcruntime140/vcruntime140_1 and msvcp140 to detect fallback.
The LLVM and MinGW notice copies in all three positive C++ packages were also
compared byte-for-byte. The maintained harness now makes that notice comparison
explicit. Its older fundamental-exception result label said 'runtime DLL RTTI';
the static import audit proves this run used bundled RTTI, and the current label
has been corrected to 'matching native runtime RTTI'. Raw old results were not
rewritten.

Execution was Wine, not native Windows: amd64 used Wine 11.21 under Rosetta on
this Mac; arm64 used Wine 10.0 in Linux arm64 Docker. Results are explicitly
CHECKED_WITH_LIMITATIONS. The amd64 static unwinder emitted a 'pc not in table'
message for a Go-side frame after successful checks; native exception handling
and the lookup-before-throw negative controls passed. This is not evidence for
exception propagation through Go. Windows signing was not performed.
Final compact records are .work/results/static-windows-<arch>-clang-final/;
raw logs are .work/static-windows/<arch>-clang-final.log. Lifecycle executable
SHA-256 values are b678202beb7967b0f822cbd8472a19cb429ab2aa96cece097303cc75b48087a6
(arm64) and b80bc97a14421df01e1921b0bcba61568c20ce2a0feaefe00437be27ef8707ff
(amd64). Archive identities and actual scratch roots are in their provenance
and artifacts.json files.

Additional Windows static compiler boundaries were investigated rather than
silently bypassed. Matching Microsoft static CRT libraries/source were obtained
from official VS payload URLs and checked against their catalog SHA-256 values;
this is an HTTPS/catalog-hash check, not an Authenticode validation. An actual
MSVC amd64 /MT /Zl exception object with libvcruntime/libcpmt failed on
/GUARDSYM:__CxxFrameHandler3,S. Bao does not discard that suppression/security
metadata. No /MT execution or complete static UCRT initialization is claimed.
The GCC amd64 static probe progressed through real libucrt wrappers and native
runtime symbol selection but rejected a .text section requiring 64-byte
alignment, beyond Go's checked 16-byte text profile. Source logs are
.work/static-windows/msvc-mt-producer.log and gcc-amd64-v8-producer.log.
Neither static compiler profile is a pass. Fully static Windows executables
also remain unavailable because stock Go imports OS DLLs.

Existing dynamic Windows profiles were checked for regressions without claiming
old executables covered changed native inputs. A scratch retranslation retained
all original source archive hashes for the seven previously executed compiler
legs. Of 47 positive packages, 32 packages (197 Go/assembly/syso files) remained
byte-identical. Fifteen GNU-profile packages changed, including reverse GNU
constructor traversal and binding-name hashes. Every changed package was freshly
linked with the new generated package and executed at GOMAXPROCS=1 and 4 using
its matching runtime DLLs. All 30 runs passed, including GCC amd64. The helper
notice wording now accommodates explicitly bundled third-party archives.
Proofs are .work/static-windows/dynamic-identity/result.json and
.work/static-windows/dynamic-regression.log; scratch Go drivers are in that
same static-windows directory. The checked producer bao-stable SHA-256 is
8b893704982a35a63c3ead070fc81b66429f5c2afe4a8572931a73c1c8758b81.
A first scratch wrapper waited on Wine service-inherited output pipes; it was
stopped with no consumer left running, and the successful rerun writes directly
to log files and checks each executable's exit status. This does not mask a
consumer error or count an interrupted wrapper as a pass.

ci/check.sh now invokes static suites after the Rust gates: all four ELF targets
in the pinned cross image, both Darwin targets with freshly built bounded LLVM
runtimes, and both native Windows LLVM-MinGW targets without the runtime DLL
search-directory argument. The existing CI source-tree cache and reusable
release-to-CI call cover these tracked inputs. No CI dispatch, hosted native
Windows execution, release publication, commit or push was performed here.
Final validation passed all 11 Bazel suites with --nocache_test_results,
Go vet, actionlint, shell syntax checks and git diff --check.

Representative reproduction (Go 1.26.10, Rust 1.99.1, Bazel 8.4.2):

```sh
ci/darwin-static-runtime.sh arm64
bazel run //:verify -- -suite static -target darwin/arm64 \
  -static-runtime-root "$PWD/.work/static-runtimes/darwin-arm64" \
  -evidence .work/results/recheck-static-darwin-arm64
# Repeat with amd64; native Intel or Rosetta execution must be available.
bao-verify -root "$PWD" -bao /absolute/path/to/bao -go /path/to/go1.26.10 \
  -suite static -target windows/arm64 -windows-driver clang \
  -windows-cc /path/to/aarch64-w64-mingw32-clang \
  -windows-cxx /path/to/aarch64-w64-mingw32-clang++ -windows-ar llvm-ar \
  -static-runtime-root /path/to/llvm-mingw/aarch64-w64-mingw32 \
  -windows-runner /path/to/arm64-wine-wrapper \
  -evidence .work/results/recheck-static-windows-arm64
# Native matching Windows hosts omit -windows-runner. CI uses native hosts.
bazel test --lockfile_mode=error --nocache_test_results //:tests
CGO_ENABLED=0 GOTOOLCHAIN=local go vet ./...
```

README contains the public archive/notice flags, static runtime matrix, platform
recipes and full-static/compiler boundaries. Earlier journal entries are retained;
all tools, source downloads, raw logs and generated artifacts stay under .work/.
Unrelated staged edits and user files were preserved.
After verification, the task-owned bao-windows-lifecycle-hold and
bao-static-linux-all sleep containers were removed, and the task Wine server
for .work/windows-wine/prefix-amd64 was stopped. No verification consumer was
running at cleanup. Downloaded tools and durable scratch evidence were retained.

## 2026-11-09: GNU Rust std on Windows amd64/arm64 and coordinated FLS teardown

Implemented and executed a Windows GNU Rust std staticlib profile on amd64 and
arm64. This supersedes the Windows Rust std exclusions in the preceding Windows
entries and the Windows no_std-only row in the previous static-runtime matrix,
within the exact GNU targets and runtime profile below. MSVC Rust targets,
Microsoft static/debug CRT startup, bigobj, ARM64EC, arbitrary Rust std API
coverage and exceptions through Go remain outside this result. OS libraries
remain dynamic; this does not establish fully static executables.

The new independent examples/windows_std crate uses Rust 1.99.1, edition 2024,
release optimization, debug=2, codegen-units=1 and panic=unwind. Its targets are
x86_64-pc-windows-gnu and aarch64-pc-windows-gnullvm. It checks an actual CRT
constructor; String/Vec allocation and OnceLock; a randomized HashMap; command
arguments/current directory; SystemTime and exclusive temporary-file creation,
write/seek/read/removal; eight std::thread workers synchronized by a Barrier and
Mutex; initialized/zero TLS and a 128-byte-aligned guard; eight worker TLS
Drop calls plus the calling thread's ninth; FLS allocation/get/set/clear/free,
null callbacks and key reuse; and catch_unwind across two RAII frames with two
Drop calls. The panic hook is restored after the caught panic. Native unwind
lookup runs before raising the panic so an omitted-metadata control cannot
attempt an invalid unwind through Go frames.

The first archive failed before translation because Rust embeds raw-dylib import
records, including bcryptprimitives.dll, among native members. The internal COFF
view now skips validated short import records and .idata declaration/thunk
objects for primary archives as well as dependency archives. It retains native
members, checks import-declaration machine types against the native architecture,
and does not derive DLL bindings from those records. The generic ar view used
for archive inspection/authentication still preserves every ordinary member.
Tests show a fabricated embedded DLL declaration cannot grant a binding; an
explicit selected mapping still wins. Mixed import/native architectures and
malformed short records remain errors rather than hidden native inputs.

Prebuilt std also exports __imp_ aliases for TLS data. A bounded, zero-addend,
eight-byte compiler alias cell now retains its ordinary address relocation to
the retained image template, matching a native linker's template address. It is
not converted into a pointer to an arbitrary thread's private storage. TLS
instructions continue through the private template-offset/TEB lowering. Other
TLS absolute pointers, code sites, extra definitions, addends and out-of-bounds
alias shapes are not accepted by this rule. Rust's embedded .llvmbc/.llvmcmd
payloads carry IMAGE_SCN_LNK_REMOVE. They are now removed even when retaining
debug information; runtime references into removed metadata fail. Previously,
alignment accessors were emitted for bitcode with no runtime address, causing
Go undefined-symbol link errors. Native EH/unwind payloads remain retained.
The OS import catalog was extended from actual matching toolchain import
libraries. It includes the synchronization API-set, ProcessPrng, filesystem,
thread, ntdll and related std references; it does not emulate those APIs.

Execution exposed a real TLS lifetime bug. The initial ARM64 translated fixture
reported zero Rust TLS drops, eight completed worker locks, nine live Bao TLS
blocks and eight destroyed blocks. Bao's FLS destructor could free a worker's
private TLS before Rust's separate FLS destructor ran. Rust then observed a new
template instead of the destructor list it had registered, and late accesses
reallocated storage during thread exit. Translation/link success was insufficient.

The authored helper now coordinates native-image FLS callbacks with that TLS
lifetime. Undefined image calls to FlsAlloc/GetValue/SetValue/Free use namespaced
adapters, except when an explicit native definition already supplies the API.
The helper's own OS imports stay direct. Registered values have private records
and real OS FLS slots. The OS callback or the image TLS destructor can drain a
record first; clearing its active state prevents a second callback. Image
cleanup drains these callbacks while its TLS slot remains available, runs native
TLS/CRT cleanup and only then releases the template/records. Registry metadata
survives key reuse until explicit quiescent Shutdown. Null-callback and explicit
FlsFree round trips are executed by the fixture. Destructor re-registration is
bounded to four rounds and persistent rearming fails fast. Managed FLS keys
cannot be passed to code outside this image: external DLL/Go FLS calls would
observe the adapter's private records. These restrictions are in README.

Both helper binaries and their provenance were regenerated with Apple Clang
21.0.0 (clang-2100.1.1.101), the maintained freestanding/unwind-table flags,
MSVC ABI targets and inline ARM64 atomics. Authored runtime.c SHA-256 is
090820a7f1ad325d229e326f8290a09e35e1808d748cd5dcf1fa16e5c35fe0b9.
The new runtime.bin hashes are
0926c8d39081db9b446733146afd996c946abfb291faacf80ad6ca54448997df (amd64)
and 4cdb9b9ae47fce9dd7a71e81dd84328ead28a2c00b314ebd319b22550186838d
(arm64). No third-party lifecycle source was copied into this helper.

cmd/bao-verify/windowsstd.go now runs after the no_std gate and before C++ in
both Windows static CI legs. Each target builds a fresh std archive and tests
both manifest-generated typed bindings and pinned PureGo v0.11.3 registration.
Each positive executable runs at GOMAXPROCS=1 and 4 with CGO_ENABLED=0 and
invalid consumer CC/CXX/RUSTC paths. All four consumers pass with nine TLS drops,
two unwind drops, eight lock updates, no TLS failure bits, the expected FLS
callback values, zero live Bao blocks and nine destroyed blocks. Explicit
Shutdown is idempotent. For each binding mode, separately linked omission
controls disable caller TLS cleanup, constructors or unwind metadata; all twelve
target/mode/control executions fail with the expected fixture failure rather
than a PASS marker. The source archive hash remains unchanged during checks.

Each std package carries byte-identical LLVM/MinGW notices plus the installed
Rust COPYRIGHT-library.html and every Rust library license (15 notices total).
The typed consumer uses only the standard library. Runtime registration uses
PureGo with its pinned checksum and offline consumer builds. The static Windows
suite's metadata now retains that PureGo dependency information instead of
incorrectly labelling the entire suite as standard-library-only.

Correction to the preceding static-runtime entry: the maintained PE executable
import audit used debug/pe.ImportedLibraries, which is an unimplemented stub in
Go 1.26.10. Its empty result did not audit executable imports. Manifest checks
and disabled runtime-DLL controls did run, and earlier standalone tool probes
remain separate evidence, but that harness check was incomplete. The verifier
now reads the actual import directory through ImportedSymbols, requires a
nonempty result and extracts its DLL names. Final consumers import only
api-ms-win-core-synch-l1-2-0.dll, bcryptprimitives.dll, kernel32.dll, ntdll.dll,
ucrtbase.dll, userenv.dll and ws2_32.dll. There are no shared language-runtime
DLLs. Windows data imports resolved with NewLazyDLL are now included explicitly
in bao-manifest.json and in -require-static-runtime checks. A data-only
libstdc++ import is a failing negative; an OS data import remains allowed.
This does not inspect arbitrary dynamic native loading or transitive OS imports.

The independent testdata/windows_std_control.c uses the ordinary native linker,
the same Rust archive and OS TLS rather than Bao's helper. It creates a caller
thread so the caller's TLS destruction can be observed after joining it. The
amd64 native control passes, including nine TLS drops and two unwind drops.
ARM64's native PE links but fails under Wine 10 with exactly:

```text
native result=3 tls=8 unwind=0 lock=8 failures=2 fls=2
```

The failure bit identifies only 128-byte TLS alignment; visitation and template
bytes pass. The PE TLS directory requests IMAGE_SCN_ALIGN_128BYTES (0x800000),
confirmed independently with llvm-readobj --coff-tls-directory and by the
maintained PE reader. Wine 10's [alloc_thread_tls implementation](https://github.com/wine-mirror/wine/blob/wine-10.0/dlls/ntdll/loader.c)
uses ordinary heap allocation without honoring that alignment. The native
control result is explicitly FAIL_ALIGNMENT_UNDER_WINE, not a native execution
pass. Only this exact diagnostic on an explicit ARM64 Wine runner, with a
verified 128-byte PE request, can proceed to Bao checks. Native Windows CI has
no such exception and must pass the native control. Bao's private ARM64 TLS
passes the same alignment and data checks under Wine, along with all subsequent
unwind/cleanup checks. This is neither a hosted Windows result nor a claim that
Rust's native control completed its later unwind phase under ARM64 Wine.

Execution environment was macOS 26.5.2 arm64, Go 1.26.10, Rust 1.99.1
(58cf8f9c3 2026-10-13), LLVM-MinGW 20261104 UCRT / Clang 23.1.5, LLVM commit
392dfff97d29b59d77e5cac6d4b6ef2585fe7117. amd64 executed with Wine 11.21 under
Rosetta; arm64 used Wine 10.0 (Debian 10.0~repack-6) in Linux arm64 Docker.
The original idle Wine image was externally pruned after the preceding cleanup,
so its pinned Dockerfile was rebuilt. This run's held image was
sha256:bbdff71a51d72531716d7688f9cebe0e12468f069aa77cafb7fd1dc7c2a91d7d.
Language DLL fallbacks were explicitly disabled for static execution. The
unwinder sometimes prints 'pc not in table' for a Go-side frame; native catches,
RAII counts and lookup-before-throw controls pass. Unwinding through Go is not
supported. No Windows signing, hosted native VM or remote CI run was performed.

Final results are .work/results/static-windows-<arch>-clang-std-audit/ with raw
.work/static-windows/<arch>-clang-std-audit.log. Scratch roots are
.work/verify-static-2494447659 (amd64) and .work/verify-static-3050001498 (arm64).
The final std archive and consumer identities are:

| Target | std archive SHA-256 | Typed executable SHA-256 | PureGo executable SHA-256 |
| --- | --- | --- | --- |
| amd64 | 3a40c5eedf0046b061ef6d7c89f8f6fa0d2ac86c66fa43a97876b12d4b5947b6 | b1123bb441c6e4ac8017cb104c5f4077f43cc8e9a88dcf1e3a0f0b301d0be8b4 | 533b18c34132c0ed4096913a6e1f428b6c0fe58e616f24f003cbe3a2bd1541fe |
| arm64 | d2c50720a35123f86f645cc99836937ba89e3c6b26009039836719853951b941 | 5982a335947f5f593dafcf9f04e948fc60c88793d5b44d02d9b1247bc9397f99 | 7195f784b4b4e160f8ff1d51c09af2d1d39a2b7c7baae02593df2ae44f3c4efd |

The same suites freshly rebuild and run the static C++ lifecycle, fundamental
throw/catch, weak and multi-file COMDAT checks after the new std gates, with
all prior lifecycle/unwind negatives. Those also passed on both architectures.
Regenerated helper changes were additionally checked against all seven existing
dynamic Windows compiler legs. Of 47 positive packages, 13 (72 Go/assembly/syso
files) remain identical to the earlier executions. All 34 changed packages were
freshly linked and ran at GOMAXPROCS=1 and 4 with the matching DLLs (68 passing
executions). An initial MSVC scratch attempt selected Wine's builtin runtime
and exited with status 5; the successful run restored the required matching
native vcruntime140/vcruntime140_1 overrides. This was not counted as a pass.
Final producer retranslation preserves all 302 native build-input files across
the 47 packages byte-for-byte against the checked inputs. Proofs and scratch
Go drivers are .work/windows-std/dynamic-{final-,}identity/, dynamic-regression.log
and final-byte-identity.log. The final producer bao-final SHA-256 is
a7717335842f047f5aeb1d3c92020e328349d7c0376565465c15290172e561ae.

Validation passed all 11 Bazel suites with --nocache_test_results, Go vet,
actionlint, shell syntax checks and git diff --check. CI already invokes the
static suite on native Windows amd64/arm64, so those jobs now require std's
native control, both binding modes and omission negatives before static C++.
No workflow dispatch, release publication, commit or push occurred. README now
contains the public GNU std recipe, notice requirements, FLS lifetime/key scope
and native-versus-Wine boundaries. Unrelated staged work and the README swap file
were preserved; scratch artifacts remain under .work/.

Representative reproduction (matching native Windows hosts omit the runner):

```sh
rustup toolchain install 1.99.1 --profile minimal \
  --target aarch64-pc-windows-gnullvm --target x86_64-pc-windows-gnu
bao-verify -root "$PWD" -bao /absolute/path/to/bao -go /path/to/go1.26.10 \
  -suite static -target windows/arm64 -windows-driver clang \
  -windows-cc /path/to/llvm-mingw/bin/aarch64-w64-mingw32-clang \
  -windows-cxx /path/to/llvm-mingw/bin/aarch64-w64-mingw32-clang++ \
  -windows-ar llvm-ar \
  -static-runtime-root /path/to/llvm-mingw/aarch64-w64-mingw32 \
  -windows-runner /path/to/arm64-wine-wrapper \
  -evidence .work/results/recheck-windows-std-arm64
# Repeat for windows/amd64 and the x86_64-w64-mingw32 prefix.
bazel test --lockfile_mode=error --nocache_test_results //:tests
CGO_ENABLED=0 GOTOOLCHAIN=local go vet ./...
```
The task-owned ARM64 Wine holder was removed after verification. No native
consumer or task Wine server remained active at cleanup; raw artifacts and
source/provenance records were retained for review.

## 2026-11-09: Classify the documented Windows profiles as supported

At the user's request, removed the experimental classification from Windows
amd64/arm64 in README, CLI help, target descriptors, generated package profile
metadata and the Windows verification suite's profile text. Updated README
heading links and corrected the verifier's stale blanket Rust std exclusion to
refer to its separate GNU std static suite. This supersedes the experimental
status wording in earlier Windows entries for the currently documented profiles.

Support covers the compiler/runtime combinations and boundaries established by
the preceding execution records. MSVC Rust targets, Microsoft static/debug CRTs,
bigobj, ARM64EC, Windows/386 and unwinding through Go retain their documented
limits. README still distinguishes Wine execution from pending native Windows
CI verification; this classification change does not claim a new native run,
signing check or release result. The existing CI gates remain required.

Validation on macOS 26.5.2 arm64 with Go 1.26.10, CGO_ENABLED=0,
GOTOOLCHAIN=local, GOENV=off and GOWORK=off:

```sh
go test ./toolchain ./cmd/bao ./cmd/bao-verify
git diff --check
```

All three test packages and the diff check passed. The affected Go files are
gofmt-clean; a source scan leaves experimental labels only on the separate Linux
profiles and unrelated Darwin implementation boundaries. Changes affect support
labels and metadata; Windows native inputs were not rebuilt or executed again.
Unrelated staged work was preserved. No commit, push or publication occurred.

## 2026-11-09: Native Windows CI startup paths and a shorter consumer overview

Investigated the reported [Windows amd64 job](https://github.com/moriyoshi/bao/actions/runs/42505080131/job/128805864595)
from run 42505080131, commit ed614b87ccdd4f6b5254be9b02f25fb81ec46a2a.
The user committed the earlier work while this review was underway; unlike the
older run inspected at the start of the release-readiness check, this run does
include the current Windows implementation. Its Windows Server 2025 image was
windows-2025-vs2026 20261103.298.1, with VS Developer PowerShell 18.11.3,
MSVC 14.51.36231, Go 1.26.10 and Rust 1.99.1. VC setup tests, toolchain setup
and Go unit tests passed. The first bao-verify invocation then failed with:

```text
bao-verify: The system cannot find the path specified.
```

No Evidence line or verifier artifacts were produced. The failure is before
native fixture compilation/execution. The original uncontextualized error does
not identify which startup path failed; this investigation does not claim an
exact failing junction/path was reproduced on a native Windows VM. Raw logs
and the formatting-stripped copy are in .work/ci-42505080131/.

ci/check.sh now explicitly converts the workspace, built Bao executable and
selected Go executable to absolute Windows paths with cygpath. Every native
verifier invocation sets MSYS2_ARG_CONV_EXCL=* so Git Bash cannot reinterpret
its already prepared paths or target arguments. The verifier normalizes path
separators and distinguishes bare PATH lookups from qualified paths. On Windows
it keeps the existing absolute executable path instead of an additional
EvalSymlinks filesystem walk; execution and file hashing use that same path.
Unix/Bazel symlink resolution is retained. Root and tool resolution failures
now identify their input path. These changes apply only to the integration
harness; consumer signature/trust-policy checks in package verify were not
relaxed. A hosted rerun is still required to establish that this fixes the
specific reported startup failure.

Added maintained regression coverage for absolute paths, paths with spaces,
Windows forward slashes, PATH lookup, symlinked tools and logical Bazel runfiles.
Using the pinned Go 1.26.10 SDK with CGO_ENABLED=0, GOTOOLCHAIN=local, GOENV=off
and GOWORK=off, go test ./cmd/bao-verify passed on macOS 26.5.2 arm64. The Windows
amd64 test executable was separately cross-compiled and the path regressions
executed under Wine 11.21/Rosetta; all five subtests passed without skips.
This is Windows-code execution under Wine, not a native Windows VM check.
The maintained Bazel verifier test target, shell syntax, actionlint and
whitespace checks also passed. Reproduction:

```sh
go test ./cmd/bao-verify
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c \
  -o .work/ci-42505080131/verify-test-windows-amd64.exe ./cmd/bao-verify
# On matching Windows, execute the .exe directly; locally this used Wine:
.work/windows-std/run-amd64.sh \
  "$PWD/.work/ci-42505080131/verify-test-windows-amd64.exe" \
  -test.v -test.run TestResolveRunfileToolPaths
bazel test --lockfile_mode=error --nocache_test_results //cmd/bao-verify:verify_test
bash -n ci/check.sh
```

At the user's request, shortened README's Windows overview from 198 to 27 lines
and placed it under Library consumers. It now covers application builds,
required DLL deployment, TLS/thread affinity, Shutdown and supported boundaries.
The compiler and Rust std build recipes are retained in a separate 66-line
Windows producer reference under Library developers, together with compiler
flags, archive/notice requirements and input limits. Corrected the generic
archive instructions to distinguish Darwin/Linux partial linking from Bao's
own Windows COFF member selection. Distribution instructions retain Windows
helper and linked-runtime notices. Detailed COMDAT, lowering and FLS findings
remain in the preceding journal entries and the maintainer section.

The removed consumer overview also contained a local-only Microsoft toolchain
under Wine recipe. Its operational details remain here rather than in the
application workflow. Keep Microsoft's notices with a disposable toolchain,
disable its vctip.exe helpers as described by the upstream msvc-wine workaround,
and use the existing ci/msvc-wine.sh path adapter:

```sh
export MSVC_TOOLS=/absolute/path/to/VC/Tools/MSVC/14.44.35207
export MSVC_ARCH=x64 WINE=wine WINEPREFIX=/absolute/path/to/disposable-prefix
export WINEDLLOVERRIDES='vcruntime140=n,b;vcruntime140_1=n,b'
bazel run //:verify -- -suite windows -target windows/amd64 \
  -windows-driver msvc -windows-cc "$PWD/ci/msvc-wine.sh" \
  -windows-cxx "$PWD/ci/msvc-wine.sh" -windows-ar llvm-ar \
  -windows-runner "$PWD/ci/wine-run.sh"
```

ARM64 needs MSVC_ARCH=arm64 and a matching ARM64 Wine runner. GNU compiler legs
need their matching runtime DLL directories. Hosted CI uses native installed
compilers and native Windows execution, rather than this Wine procedure.
No compiler or runtime redistribution is authorized by this recipe.

The v0.1.0 readiness review remains gated on successful hosted checks for the
release source. In run 42505080131, unit, Darwin arm64 and both Linux jobs passed;
both Windows jobs failed, and Darwin amd64 was still running when inspected.
The older successful v0.0.0 rehearsals do not validate this changed tree. Release
assets currently cover the six documented Darwin/Linux CLI hosts. No release,
tag, commit, push or workflow dispatch was performed by this agent. The existing
README swap file and user changes were preserved.

## 2026-11-09 Windows package publication after successful DWARF translation

The next user-reported Windows CI failure reached translation successfully:
three COFF objects, three system imports, two initializer tables and three native
unwind tables. Publication then failed with "Cannot create a file when that file
already exists." This is a separate failure from the preceding startup-path
investigation: the new log establishes that the verifier now starts the producer.

The shared publisher created an empty destination reservation with os.Mkdir,
then renamed the staged package over it. That works on the supported Unix hosts.
In pinned Go 1.26.10, Windows syscall.Rename uses MoveFileW, which refuses an
existing destination, including an empty directory. Microsoft's API contract is
documented at https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilew.
The original Windows toolchain test executable reproduced this failure under
Wine before changing the publisher; its log reports "File already exists."

Split publication by host. Unix keeps its existing implementation; Windows
checks that the source is a directory and directly uses the non-replacing move.
The producer already stages beside the destination, keeping the move on one
volume. No destination is deleted or replaced. An existing file or directory,
or another producer winning the publication race, leaves the losing stage
intact. Windows errors now identify both publication paths. Added regression
tests for those preservation properties, racing producers, invalid sources and
the actual build/translate CLI paths with runtime/generated bindings and spaces
in the output path. The Windows CI unit-test step now includes toolchain and
cmd/bao before integration fixtures. Moved the existing POSIX shell linker
failure fixture into the existing !windows test file; its Unix coverage remains.

Verification used macOS 26.5.2 arm64, pinned Go 1.26.10 with CGO_ENABLED=0,
GOTOOLCHAIN=local, GOENV=off and GOWORK=off, and Bazel 8.4.2. macOS tests for
toolchain and cmd/bao, go vet for those packages, all 11 uncached Bazel test
targets, bash syntax, actionlint and git diff --check passed. Complete applicable
Windows amd64 toolchain and cmd/bao test executables passed without skips under
Wine 11.21/Rosetta. Windows arm64 test executables for both packages compiled;
they were not executed in this investigation. This is not a native Windows VM
verification. Reproduction with the pinned SDK selected as go:

```sh
go test ./toolchain ./cmd/bao
go vet ./toolchain ./cmd/bao
GOOS=windows GOARCH=amd64 go test -c \
  -o .work/ci-windows-publish/toolchain-after.exe ./toolchain
GOOS=windows GOARCH=amd64 go test -c \
  -o .work/ci-windows-publish/bao-tests.exe ./cmd/bao
.work/windows-std/run-amd64.sh \
  "$PWD/.work/ci-windows-publish/toolchain-after.exe" -test.v
.work/windows-std/run-amd64.sh \
  "$PWD/.work/ci-windows-publish/bao-tests.exe" -test.v
bazel test --lockfile_mode=error --nocache_test_results //:tests
```

Also freshly compiled examples/windows_runtime/native.c, native.cpp and
testdata/bindings_integration.c for x86_64 Windows using LLVM-MinGW 20261104
UCRT Clang 23.1.5. Each used -O2 -g -ffreestanding -funwind-tables
-fno-omit-frame-pointer; the C++ source additionally used -std=c++20. Packed
the three objects with llvm-ar rcS. A freshly built Windows Bao executable ran
under Wine with native Windows paths and the exact failing nine-symbol command:

```sh
bao.exe build -target windows/amd64 -o dwarf-native -bindings dwarf \
  -symbol bao_windows_run -symbol bao_windows_cpp_run \
  -symbol bao_scalar_ints -symbol bao_scalar_floats -symbol bao_scalar_mixed \
  -symbol bao_scalar_narrow -symbol bao_scalar_pointer -symbol bao_scalar_wait \
  -symbol bao_scalar_u32 library.a
```

It reported the same 3/3/2/3 translation counts and successfully published the
typed package. Copied that package into a scratch module with the exact maintained
typed consumer from cmd/bao-verify/windows.go, then freshly linked it with Go
for windows/amd64, CGO_ENABLED=0 and CC/CXX/RUSTC pointing to unavailable tools.
The resulting executable passed under Wine: scalar integer/FP/mixed/spilled
arguments, pointers, scheduler transition, constructor, native unwind lookup and
C++ scope cleanup. No cached consumer executable was used to validate changed
inputs. This fixture does not establish every compiler/runtime combination;
the complete native Windows CI matrices still need to run on the updated tree.

Raw baseline/fixed test logs, fresh native objects/archive, Windows producer,
published package, consumer and execution log are in .work/ci-windows-publish/.
The input archive SHA-256 is
93671cc8cfb46b7a429a993d9c9fb743dbadf2a61be39a77f2612a24b551e4c9;
the Windows producer is
6dcaaabaa655a738e915e505ed7c5f99ea018680b7ca1276dbbcd3155100f02a;
the executed consumer is
ed987017bcf5d100ae00e6391179c0e4322bf5532a0dcf3185a1e3732dd7312c.
No commit, push, tag, release or workflow dispatch was performed.

## 2026-11-09 Host-native compiler guards in consumer verification

The next native Windows CI log passed pecoff, bindings, toolchain, cmd/bao and
cmd/bao-verify unit tests, then failed the DWARF consumer build with
"CC environment variable is relative; must be absolute path: /bao-no-cc".
Windows Go validates CC, CXX and FC before building, even with CGO_ENABLED=0.
Unlike Unix Go, Windows Go does not consider a drive-less /bao-no-cc absolute.
This corrects the verification scope of the preceding publication entry: its
consumer was cross-linked with macOS Go and then executed under Wine. That
established publication and consumer runtime behavior, but did not exercise
the Windows Go executable's environment validation.

Added one consumerEnv helper for all host-side compiler-disabled build paths.
It derives unavailable compiler paths from the host's absolute scratch path,
sets CGO_ENABLED=0 and preserves target overrides. CC, CXX and FC are quoted
using Go's argument-list convention without escaping backslashes; RUSTC remains
a single unquoted executable path. This handles scratch paths containing spaces.
Applied it across Windows DWARF/manifest/runtime, Rust no_std/std, lifecycle,
exceptions, weak externals, COMDAT and static-runtime checks, and shared consumer,
signature and release checks. Other host cross-builds use the same helper.
Docker command strings retain Linux paths, since those are interpreted inside
the Linux container. Producer compiler settings remain available for compilation.

Added maintained tests for host-absolute unavailable guards, target overrides
and paths with spaces. A real host Go subprocess builds a fresh pure Go consumer;
the negative control changes its source to import C and enables CGO, requiring
failure specifically on the unavailable compiler path. Native Windows CI's
existing cmd/bao-verify test step runs this test. Bazel declares its pinned SDK
runner as test data and supplies BAO_VERIFY_TEST_GO; the test supplies writable
cache and GOPATH directories when the sandbox does not provide absolute ones.
An initial Bazel run exposed the missing cache default in the new test; after
fixing the test environment, the maintained target passed with the declared SDK.

Verification used macOS 26.5.2 arm64, Go 1.26.10, Bazel 8.4.2 and Wine 11.21
under Rosetta. Downloaded the official Go 1.26.10 windows-amd64 SDK into
.work/ci-windows-compiler-env/ and executed its go.exe under Wine. The original
environment reproduced the exact reported CC error (exit 1). Corrected absolute,
quoted CC/CXX/FC values allowed Windows Go to freshly link the exact maintained
typed Windows consumer in a scratch directory containing spaces. The native
package bytes came from the preceding publication investigation's freshly
compiled Clang archive; no native inputs changed in this guard-only fix. The
new executable passed under Wine, reporting scalar ABI/FP/mixed/spills/pointers/
scheduler, constructor, native unwind lookup and C++ scope cleanup. Its SHA-256
is d48be251d4cefb0dbf882e21511fbe8270b2f606dadec6974dc98d69b0c2fc27.
This time Windows Go performed the linkage; no prior consumer executable was
used as evidence. Baseline/fixed command files, logs and executable remain in
that scratch directory. These are emulated Windows checks, not native VM checks.

macOS verifier tests passed, including the real Go build and CGO negative
control. All applicable Windows amd64 verifier tests passed without skips under
Wine with the Windows SDK on WINEPATH, including the same positive/negative
build test. Windows arm64 verifier tests compiled but were not executed.
The maintained Bazel verifier target, go vet ./cmd/bao-verify, formatting and
git diff --check passed. Reproduction with the pinned SDK selected as go:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local GOENV=off GOWORK=off go test -count=1 -v ./cmd/bao-verify
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c \
  -o .work/ci-windows-compiler-env/verify-tests.exe ./cmd/bao-verify
# WINEPATH contains the downloaded Windows SDK's bin directory, as a Windows path.
WINEPATH='Z:\Users\moriyoshi\Source\bao\.work\ci-windows-compiler-env\go\bin' \
  .work/windows-std/run-amd64.sh \
  "$PWD/.work/ci-windows-compiler-env/verify-tests.exe" -test.v
bazel test --lockfile_mode=error --nocache_test_results //cmd/bao-verify:verify_test
go vet ./cmd/bao-verify
```

The full native Windows compiler/runtime matrices still require a hosted rerun;
this investigation does not establish their complete success. This agent did
not commit, push, tag, publish or dispatch workflows; the user updated HEAD
independently while the work was in progress.

## 2026-11-09 Linux CI sandbox defaults and source revision check

Read both reported run 42510210430 logs through the GitHub API. Job
128821514007 (linux-arm64) and job 128821513787 (unit on linux-amd64) both failed
TestConsumerBuildWithGo: "build cache is required, but could not be located:
GOCACHE is not defined and neither $XDG_CACHE_HOME nor $HOME are defined".
Each ran source 8a6ae36256732a8d9965954a692d39398cc0a5b1. Inspection of that
revision confirms that the test used /usr/bin/go from PATH and omitted its own
cache fallback. This was the intermediate revision before the preceding entry's
explicit Bazel SDK dependency and GOCACHE/GOPATH fallback were included. Both
fixes are already present in the current checkout at df7c946592cdbb65472231ba23e2a123ee7a01ff.
Both reported jobs missed the successful-result cache and actually ran tests;
this failure is not stale cached success or a Windows compiler-guard regression.

Strengthened the maintained test to explicitly clear HOME, XDG_CACHE_HOME,
GOCACHE and GOPATH before constructing the consumer harness. This forces the
sandbox case even when a developer's shell supplies working defaults. Kept
the real Go subprocess and the CGO-enabled unavailable-compiler negative control.

With Go 1.26.10 and Bazel 8.4.2 on macOS 26.5.2 arm64, all 11 uncached Bazel
test targets passed, including the strengthened verifier test with its declared
SDK. Cross-compiled the current verifier tests for Linux arm64 and amd64, and
downloaded the official matching Go 1.26.10 SDKs into .work/ci-42510210430/.
Ran them in existing bao-static-linux:arm64/amd64 Docker images with network
disabled, a read-only root and scratch mount, and an executable /tmp tmpfs.
The images' ordinary go command is gccgo 14.4.0, so BAO_VERIFY_TEST_GO explicitly
selected the downloaded SDK. Linux arm64 executed in the local Colima arm64 VM;
all verifier tests passed without skips, including both build controls.

The amd64 Docker attempt under the local foreign-architecture emulator failed
inside the Go SDK with corrupted compiler arguments. A serial retry with
GOMAXPROCS=1, GOFLAGS=-p=1 and GODEBUG=asyncpreemptoff=1 instead faulted in
os.(*File).readdir. An independent, plain Go hello-world build with a minimal
environment and no Bao code also crashed. No amd64 execution pass is claimed;
native amd64 CI remains required. No workaround for this local emulator failure
was added to the project or CI. Raw job metadata/logs are .work/job-128821*.json
and .log; local verification logs and SDKs are .work/ci-42510210430/.
Reproduction from the workspace with the pinned SDK selected as go:

```sh
bazel test --lockfile_mode=error --nocache_test_results //:tests
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c \
  -o .work/ci-42510210430/verify-tests-linux-arm64 ./cmd/bao-verify
docker run --rm --pull=never --platform linux/arm64 --network none \
  --read-only --tmpfs /tmp:exec -v "$PWD/.work/ci-42510210430:/work:ro" \
  -e BAO_VERIFY_TEST_GO=/work/sdk-arm64/go/bin/go bao-static-linux:arm64 \
  /usr/bin/env -u HOME -u XDG_CACHE_HOME -u GOCACHE -u GOPATH -u GOROOT \
  /work/verify-tests-linux-arm64 -test.v
```

Formatting and git diff --check passed. No commit, push, workflow rerun or
release was performed. Rerunning old source would retain the old failure;
hosted checks must use the revision containing the SDK/cache fixes.
## 2026-11-09: Darwin typed bindings with cgo and internal linking

Generated Darwin typed adapters now compile when cgo is enabled. They import
runtime/cgo in that mode and exclude the bundled fakecgo bootstrap, including
the previously untagged assembly defining crosscall2. The cgo-disabled path
still uses the existing bundled bootstrap. This allows a real cgo dependency
in the same application when Go's internal linker is selected. Other target
profiles and PureGo runtime registration were not changed. Generated packages
must be regenerated to receive the new files and constraints.

Verification used macOS 26.5.2 arm64, stock Go 1.26.10, Apple clang 21.0.0,
Rust 1.99.1 and Cargo 1.99.1. With GOROOT unset, built fresh CLI and verifier
from source using `go build -o .work/cgo-investigation/bao ./cmd/bao` and
`go build -o .work/cgo-investigation/verify ./cmd/bao-verify`, then ran:

    .work/cgo-investigation/verify -suite bindings -target darwin/arm64 \
      -bao "$PWD/.work/cgo-investigation/bao" \
      -go /Users/moriyoshi/.local/share/mise/installs/go/1.26.10/bin/go \
      -evidence "$PWD/.work/cgo-investigation/results-release"

The suite freshly compiled native C and Rust, generated manifest and DWARF
bindings, linked and executed cgo-disabled consumers, and checked their ad-hoc
Hardened Runtime signatures. It separately linked and executed cgo-enabled
consumers with `-ldflags=-linkmode=internal`, first with no application cgo
dependency and then with a real package calling a C function. Both binding
modes and the Rust std fixture ran; the latter exercises panic/RAII and TLS
destruction. The cgo-dependent variants ran at GOMAXPROCS=1 and 4. Cgo-enabled
executables were not separately signed. `go test ./bindings ./cmd/bao-verify`
passed with Go 1.26.10. The existing Rust unwind negative control passed.

For a negative control, a default cgo-enabled build of the newly generated
bindings-dwarf fixture failed at link time with missing-section errors; Bao's
Darwin ELF containers are incompatible with the default external link path.
Consequently plain `go build` with cgo enabled remains unsupported unless the
consumer selects internal linking, and cgo dependencies requiring external
linking remain unsupported. Darwin amd64 and other Go versions were not tested
for this path. Scratch inputs and logs are under .work/cgo-investigation and
.work/verify-bindings-1094443838. This entry supersedes the earlier blanket
statement that typed Darwin bindings cannot be combined with runtime/cgo.

## 2026-11-09: Linux and Windows typed bindings with cgo

Extended the generated typed adapters to Linux and Windows when cgo is enabled.
Linux excludes the fakecgo bootstrap and imports runtime/cgo; its generated
binding requires Go's internal linker. Windows retains Go's native Windows
runtime transition. With cgo enabled, an initial Windows test crashed in a
native imported function because Go represented a dynamic import as a code
thunk where the COFF code expected a pointer slot. Windows generation now
allocates image-private function pointer slots and initializes them from the
named DLLs before native initializers, for both binding modes and cgo settings.
This also changes the earlier Windows dynamic-import implementation; the native
runtime behavior and broader platform matrix need their normal CI verification.

Added `ci/cgo-linux.sh` to build a fresh C/TLS scalar fixture and a real separate
cgo package, and expanded the Windows suite's LLVM-MinGW typed legs with cgo
controls. Generated artifacts must be regenerated. The CLI and README now
describe the internal-linker requirement; PureGo mode remains unchanged.

On macOS 26.5.2 arm64, Go 1.26.10, `go test -count=1 ./bindings ./pecoff
./cmd/bao ./cmd/bao-verify` and `go vet` for those packages passed. With the
Linux arm64 Go 1.26.10 SDK and GCC 14.4.0/binutils 2.44 in the local native
Colima Linux arm64 VM, the following built fresh producer and native objects,
then linked and executed cgo-enabled consumers with and without a separate cgo
dependency and a cgo-disabled control. The separate dependency variants ran
at GOMAXPROCS=1 and 4. The fixture checked scalar ABI, pointer lifetime,
scheduler progress and native TLS finalization:

    docker run --rm --pull=never --network none --platform linux/arm64 \
      -v "$PWD:/repo" -v "$PWD/.work/ci-42510210430/sdk-arm64/go:/sdk:ro" \
      -w /repo -e PATH=/sdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      -e GOTOOLCHAIN=local -e GOPROXY=off -e GOWORK=off \
      -e GOCACHE=/repo/.work/cgo-other/linux-cache \
      -e GOPATH=/repo/.work/cgo-other/linux-gopath \
      --entrypoint /bin/sh bao-static-linux:arm64 ci/cgo-linux.sh

Go's default external linking failed on the Linux fixture with unsupported
relocations and missing native sections; internal linking passed. The Linux
amd64 Docker emulator was killed before completing its build, so no amd64
execution is claimed. Linux loong64 and ppc64le cgo execution was not checked.

Windows amd64 was cross-compiled with Go 1.26.10 and LLVM-MinGW 20261104 and
executed under local Wine on macOS arm64, not native Windows. Fresh manifest
and DWARF C/C++ fixture consumers passed at GOMAXPROCS=1 and 4 with cgo and
internal linking, including a real cgo call, native constructors, imported
functions, unwind lookup and scalar ABI. Cgo-disabled controls and constructor
and unwind negative controls also passed. The cgo-enabled no-other-dependency
control passed separately. Default external linking of the broader fixture
failed with undefined import slots. A Windows arm64 scalar cgo consumer compiled
and linked with internal linking, but was not executed. Windows CI's new cgo
controls have not run on native Windows. Raw artifacts are in
.work/cgo-linux-Lc7KxN, .work/cgo-other and .work/verify-windows-960459213.

Separately added a real cgo dependency to the freshly generated Windows amd64
lifecycle fixture, linked with Go's internal linker and executed it under Wine
at GOMAXPROCS=1 and 4. Both runs passed C/C++ initialization, CRT allocation,
throw/catch/rethrow, native threads, TLS destructors and explicit shutdown.
Wine's libunwind printed a `pc not in table` diagnostic; the fixture's checks
still passed. The Windows verifier now includes this cgo lifecycle case for its
LLVM-MinGW leg; the expanded verifier itself still needs native CI execution.

The broader Windows amd64 verifier using Wine completed with
`CHECKED_WITH_LIMITATIONS`, including cgo-disabled Rust, PureGo and C++ lifecycle
checks and their negative controls, plus the new cgo scalar checks. It used the
verifier built before the later no-other-cgo-dependency and lifecycle checks
were added; those two checks were run separately as described above. The ARM64
cross-link check was repeated using a fresh native C object with two system
imports, one initializer table and unwind metadata; linkage succeeded, but the
result was not executed. No Windows signing or native Windows CI was run.

## 2026-11-09: Explain cgo-enabled builds in the FAQ

Added a FAQ answer for applications with third-party cgo dependencies, covering
regeneration, the internal linker, tested targets and remaining limitations.
Updated the compiler answers to distinguish cgo-disabled consumer builds from
cgo-enabled applications. This summarizes the preceding cgo verification and
does not add a platform support claim.

Verification on macOS arm64: `git diff --check -- README.md JOURNAL.md` passed;
the new FAQ links were checked against the current README headings. No code,
compilation, linkage, native execution or signing checks were involved.

## 2026-11-09: Library author and consumer walkthrough

Added a self-contained README walkthrough based on the sibling `bao-test`
example's C `add` archive, DWARF-inferred typed binding and Go consumer. The
walkthrough separates the author and application into two modules with a local
replacement, explains distribution, and shows cgo-disabled and cgo-enabled
internal-link builds. It does not depend on files or paths in the sibling
checkout. Existing README and journal edits were preserved.

On macOS 26.5.2 arm64, used Go 1.26.10, Apple clang 21.0.0, SDK 26.5 and a
fresh Bao CLI built from the current workspace. Extracted the four shell blocks
from the README into `.work/readme-walkthrough/replay/commands.sh` and ran them
in a new `.work/readme-walkthrough/replay` directory with GOROOT unset,
GOTOOLCHAIN=local, GOWORK=off, GOPROXY=off and an isolated workspace GOCACHE.
The commands compiled the C source, generated the archive and typed package,
linked fresh cgo-disabled and cgo-enabled Go executables, and executed both
natively; each printed `3`. The cgo-enabled example contains no separate cgo
dependency. Reproduction from the replay directory, after placing the fresh Bao
CLI and Go SDK on PATH:

    env -u GOROOT GOTOOLCHAIN=local GOWORK=off GOPROXY=off \
      GOCACHE="$PWD/../../cgo-investigation/cache" sh commands.sh

The replay requires a fresh directory because Bao refuses an existing output
directory. No signing or cross-platform execution was performed. Scratch files
remain under `.work/readme-walkthrough/`.

## 2026-11-09: Rename the walkthrough package

Changed the author/consumer walkthrough's generated package directory and Go
package name from `bin` to `native`, including the build command, distribution
instructions, import and call. The sibling reference and other files were not
changed.

Replayed all four README shell blocks in the fresh
`.work/readme-walkthrough/native-replay` directory on macOS 26.5.2 arm64 with
Go 1.26.10, Apple clang 21.0.0 and SDK 26.5. The current Bao CLI compiled the
C archive and generated the typed package; both cgo-disabled and cgo-enabled
internal-link applications linked and ran natively, each printing `3`. The
cgo-enabled example has no separate cgo dependency. The replay command is in
`.work/readme-walkthrough/native-replay/commands.sh`; it requires a fresh
working directory and Bao/Go on PATH. No signing or cross-platform execution
was performed. `git diff --check -- README.md JOURNAL.md` passed.

## 2026-11-09: gpui-go handoff: amd64 GOT binds, Windows imports, Linux libraries, diagnostics

Handoff input: gpui-go `.agents-workspace/tmp/release-pipeline/bao-handoff/HANDOFF.md`,
issues 1, 2 and 4, then a requested diagnostics feature. Inputs were the real
GPUI archives from that evidence directory and hosted run 42562229131. Toolchain:
Go 1.26.10, Rust 1.99.1 archives, LLVM-MinGW 20261104, macOS 26.5.2 arm64 host.

Issue 1, darwin/amd64 launch abort. The handoff's theory of a missing section was
wrong: the boundary symbols were already defined. Go's amd64 adddynrel rewrites
GOTPCREL to LEA only for a MOV. Other forms (CMP, ADD) reach AddGotSym, which on
Darwin binds the defined symbol by name, and dyld aborts. The binary had four
such flat-namespace binds, including two bytes crate vtables, so a fix limited to
boundary symbols would have moved the abort. New pass
`localizeAMD64GOTReferences` gives X86_64_RELOC_GOT references to native-defined
symbols a private slot in `__bao_local_got`. `__eh_frame` personality fields and
undefined imports are unchanged.

Verification, regenerated from the real archive and overlaid on a scratch copy of
the evidence module, so gpui-go's Darwin import rewrite stayed in place:
- Negative control, pre-fix binary: native execution on an Intel i9-9880H, macOS
  26.6.2 (macbook-pro-2.local): dyld abort, exit 134. Same abort under Rosetta.
- Fixed binary: zero flat-namespace binds. `-smoke` exit 0 under Rosetta, and
  natively on the Intel Mac at GOMAXPROCS 1 and 4.
- darwin/arm64 regeneration: all three .syso byte-identical to the evidence.
Hosted macos-15-intel was not run.

Issue 2, Windows translation. Three separate causes:
- `SysFreeString` was reached by `jne` (0F 85 rel32), which the direct-branch
  check missed. Jcc now counts; a RIP-relative ModRM cannot be 0x80-0x8f, so the
  guard against data references holds. LEA and MOV remain rejected.
- The handoff's 40 names were an undercount, since errors arrived one at a time.
  Collecting them showed 237 on amd64 and 238 on arm64. A catalog was rejected.
  `-windows-import-library` takes producer-named short-import libraries. This
  keeps the earlier decision that import records in native inputs grant nothing;
  `TestEmbeddedImportDoesNotAuthorizeDLL` still passes.
- Go reported findfunc bucket overflow (344 and 261 functions). New
  `foldTextAliases` folds Rust/Itanium and local aliases, like the Darwin pass,
  leaving 15 aliases from about 6,900.

STILL BLOCKED in the repository: three read-only sections per architecture
request 64-byte alignment, above the recorded 32-byte limit, and Go's PE path
cannot request more. The limit was not changed. Only a scratch copy with the
limit lowered got further: translation and successful linkage of the gpui-go
counter for windows/amd64 and windows/arm64. Neither binary was executed; no
Windows host or Wine was available. Issue 2's completion criterion
(release:smoke on windows-2025 and windows-11-arm) is not met.

Library set used for that link, for both architectures: kernel32 user32 gdi32
ole32 oleaut32 shell32 shcore dwmapi imm32 propsys uxtheme advapi32 ws2_32
userenv bcrypt ntdll d3d11 dxgi d3dcompiler_47 dwrite dcomp comctl32 ktmw32
uiautomationcore windowsapp ucrtbase.

Issue 4, `-linux-system-library`. Native execution in an Ubuntu 24.04 arm64
container, using the evidence prelinked object (pl/combined.o): `-smoke` exit 0 at
GOMAXPROCS 1 and 4. Controls: no flag gives 43 unresolved names; a nonexistent
library gives `missing target library`. linux/amd64 was not run. Of the five
libraries in gpui-go's patch, the object directly needs three: libxcb.so.1,
libxkbcommon.so.0 and libxkbcommon-x11.so.0.

Diagnostics. `-v`, `-vv`, `-trace`, `-report` and `-assume-consumer` on build,
translate, inspect and doctor, in `cmd/bao/diagnostics.go`. Checks:
- Plain and -v builds of the darwin/amd64 archive: 36 of 38 files byte-identical.
  bao-build.json and bao-debug.json differ the same way between two plain runs
  (random temp paths in the linker commands), which predates this work.
  Plain and -v Windows failure: both exit 1, no package.
- `inspect -v` on the pre-fix amd64 binary reports 4 flat-namespace binds. The
  fixed binary reports none, with 792 manifest imports compared.
- Ordinal corruption, true positive: an unconsolidated darwin/arm64 package with
  a consumer importing net has 16 dylibs. Native execution aborts in dyld, and
  `inspect -vv` names 53 binds, for example `_class_addIvar` at ordinal 0.
- An early version compared the wrong manifest keys and reported a false OK with
  1 import. It now reads the published keys, and an empty comparison is SKIPPED.

Not implemented: `verified-build -v` findfunc classification; relocation tracing
for COFF objects; final-bind checks for ELF and PE executables. `-trace` reads
artifacts between stages rather than hooks inside each translator pass, so
boundary synthesis and alias folding are labeled inferences. Handoff issues 3,
5 and 6 were not addressed.

Commands: `go test ./...`; scratch reproduction under `.work/handoff-20261109/`.

## 2026-11-09: Opt-in Windows data alignment cap

Supersedes the "STILL BLOCKED" result in the earlier 2026-11-09 gpui-go handoff
entry. The 32-byte data limit and the recorded decision to fail above it remain the
default. At the user's direction, `-windows-max-data-alignment 32` links read-only
data sections requesting more at 32 bytes. Writable data, code and other values
still fail. The generated runtime check uses the applied value. Capped sections
appear in `windows_capped_alignments` in bao-manifest.json, on stderr, and as
`BAO-COFF-ALIGNMENT-CAPPED` (WARN) in diagnostics.

GPUI has three such sections on each architecture, all 64-byte requests. On arm64
they are the pxfm EXP2FT table, zmij STATIC_DATA and utf_types UTF8_DATA; the
amd64 archive merges them under `.rdata`. Whether any code relies on 64-byte
alignment was not audited; the expected purpose is cache behavior.

Verification on macOS 26.5.2 arm64 with Go 1.26.10, LLVM-MinGW 20261104 and the
hosted archives from run 42562229131, using the 26 import libraries listed in the
earlier entry plus the handoff's -link-archive set:
- Negative control, no flag: exit 1 on both architectures, no package.
- With the flag: translation exit 0; 677 amd64 and 663 arm64 objects. They are
  byte-identical to the earlier scratch probe.
- Successful linkage of gpui-go examples/counter (gpui, gpui_prebuilt,
  gpui_headless, CGO_ENABLED=0): PE32+ x86-64 and PE32+ AArch64 executables.

No Windows execution occurred. Neither the arm64 host nor the Intel Mac has Wine.
Issue 2's completion criterion, release:smoke on windows-2025 and windows-11-arm,
remains unmet until those hosted runners execute it.

## 2026-11-09: Settings file for build and translate

`bao build` command lines had grown large (gpui-go's Windows build needs 26
import libraries plus link inputs and notices). Added `-settings FILE` to `build`
and `translate`, in `cmd/bao/settings.go`. Decisions:

- JSON with `schema: 1`, decoded with `verify.Decode`, so unknown keys, duplicate
  keys and trailing values fail. There is no auto-discovery: a file changes what
  is built, so it must be named.
- Settings go through the existing flags with `flag.Set`, so validation stays in
  one place. A flag given on the command line replaces that whole setting, even
  for repeatable flags, because order matters (first import library wins).
- `bindings` is a manifest path, `dwarf`, or an inline manifest. Inline manifests
  use the same `bindings.Parse` as files.
- Paths are relative to the settings file. `${VAR}` expands in paths and an unset
  variable fails. `darwin`, `linux` and `windows` sections apply only to their
  target, and each section's link inputs follow the common ones. A setting a
  command cannot use is an error rather than being ignored.
- `-o` and the diagnostics flags stay on the command line.

Verification on macOS 26.5.2 arm64, Go 1.26.10, LLVM-MinGW 20261104 and the hosted
archives from run 42562229131. One 3.3 KB settings file, with inline bindings and
`${MINGW}` for the per-architecture prefix, was used for both Windows targets:
translation exit 0, and all 688 amd64 and 674 arm64 generated files byte-identical
to the earlier flag-driven builds, including bao-build.json. Negative control: an
unset variable fails before translation. This is translation only; the Windows
smoke remains unrun, as recorded in the previous entry. `go test ./...` passed.

The README was open in an editor during this work, so its settings section is
not yet written.

## 2026-11-09: README settings section

Added the "Settings files" section to README.md, which the previous entry recorded
as not yet written. Documentation only; no behavior changed.

## 2026-11-09: Default settings file

Supersedes the "no auto-discovery" decision in the settings file entry, at the
user's request. Without `-settings`, `bao build` and `bao translate` use
`.bao.config.json` from the working directory if it exists. Parent directories
are not searched. A stderr line names the file because it changes the build, and
`-settings ''` opts out. An unreadable or invalid default file is an error rather
than being skipped.

A settings file can set `ld`, so building in an untrusted checkout with an
explicit archive input can now run a linker that checkout names. Previously only
Cargo inputs ran code from the checkout. `go test ./...` passed; the behavior is
covered by `TestDefaultSettingsFile`.

## 2026-11-09: Rename -settings to -config

Renamed the flag to `-config` to match the `.bao.config.json` default. It was
unreleased, so no `-settings` alias exists. Earlier entries keep the old name.
`bao build` and `bao translate` behavior is otherwise unchanged.

## 2026-11-09: Target variables in config files

Added `${BAO_GOOS}`, `${BAO_GOARCH}` and `${BAO_CPU}` to config-file paths, so a
file can name per-architecture toolchain directories without a caller-set
variable. They take precedence over the environment. `BAO_CPU` is the first field
of the target's Rust triple. They are rejected in `input`, because an `auto` target
is detected from that file.

Chose this over per-architecture override sections, which would need merge rules
that nothing requires yet: gpui-go's only per-architecture difference is a path.
