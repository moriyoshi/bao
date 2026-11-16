# Linux targets

Reference for producing packages for linux/arm64, linux/amd64, linux/loong64
and linux/ppc64le. [Platform support](../README.md#platform-support) lists
where each target has run.

## Building

`bao build` and `bao translate` handle Linux ELF64 relocatable code for each
target, independently of the Darwin container workaround. They read system
exports from actual target glibc/libgcc shared libraries in a producer sysroot. The final executable is
Linux ELF and uses the stock Go internal linker.

On a Linux arm64 producer, build from a Rust archive:

```sh
bao build -target linux/arm64 -sysroot / \
  -symbol bao_example_run -o ./native /path/to/libnative.a
```

The consumer needs Go, optional PureGo for runtime binding mode, and compatible target system libraries; it needs
neither the producer sysroot nor a native compiler. See
[using generated Go packages](../README.md#using-generated-go-packages) for consumer builds.

Imports normally resolve against the glibc and C++ runtime libraries. Name other
sysroot libraries with `-linux-system-library libxcb.so.1` (repeatable). Each
must exist in the sysroot, and it cannot replace a symbol the standard set
already exports. The consumer machine must provide the same library.

## Target profiles

Every Linux target expects glibc and one combined native image. On arm64,
native TLS must use descriptors (TLSDESC); other native TLS models, native IFUNC
definitions, preinit arrays and static musl are not supported. A linked shared
object is accepted as described in [shared objects](#shared-objects). The
sections below add each architecture's profile.

### amd64

`build -target linux/amd64 -sysroot /` accepts PIC ELF64 archives with a target
glibc sysroot and GNU linker. The checked C++ profile is GCC 14.4.0 or Clang
19.1.7 with GCC's libstdc++, glibc 2.41 and GNU ld 2.44. It supports
exceptions caught inside C++, RAII cleanup, aligned TLS/destructors, native
constructors, imported data, and explicit static finalization in one combined
native image. Both runtime registration and DWARF-inferred assembly bindings
are checked. See the [Docker examples](../examples/cpp_linux/README.md), which also
cover Linux arm64 with both compilers. Rust std is checked in the
[static-runtime profile](../README.md#linux-runtimes); Clang with libc++ is
unverified. Exceptions must stay inside native code; Go process exit does not
run C++ static destructors. Explicit TLS/static finalization must follow the
last native use.

### loong64 and ppc64le

Linux loong64/glibc and ppc64le/glibc ELFv2 are separate experimental
profiles. Their Rust runtime and typed-binding examples and their GCC 14.2 and
Clang 19.1.7/libstdc++ C++ lifecycle suites run under QEMU; see
[platform support](../README.md#platform-support). The source CI gate requires Rust examples
from the same cross image before those C++ legs; release reuses the validated
CI results. See the [cross-image recipe](../testdata/toolchains/README.md) and
[C++ checks](../examples/cpp_linux/README.md).

## Imports and symbol versions

Each import binds a symbol version, as a static linker records one: the
default (`@@`) version that the sysroot library defines, such as
`pthread_cond_init@GLIBC_2.3.2` on x86_64. The generated directive is
`pthread_cond_init#GLIBC_2.3.2`, which Go's linker records as a version
requirement. An unversioned reference would bind the oldest version instead.
On x86_64 that is `GLIBC_2.2.5`, the compatibility ABI, whose
`pthread_cond_init` rejects a `CLOCK_MONOTONIC` condition attribute.

The default versions set the oldest glibc that can load the result. That is
the sysroot's own release for symbols whose default changed recently, such as
`pthread_condattr_setclock@GLIBC_2.34`. To keep the floor that the inputs
were built for, pass `-linux-max-symbol-version GLIBC_2.17` (repeatable, one
per namespace such as `GLIBCXX_3.4.19`, or `"max_symbol_versions"` in the
`linux` config section). Imports then bind the newest version at or below the
cap. An import with no such version stays unversioned and is printed, and
`linux_imports_above_version_cap` in bao-manifest.json lists it. The result
loads on an older glibc, but fails if that import is bound there. Read that
list before relying on the cap:

- bao's own TLS runtime calls `__cxa_thread_atexit_impl`, from glibc 2.18,
  the first time a thread uses native TLS, and aborts if it fails. An image
  that uses native TLS therefore needs glibc 2.18 whatever the cap.
- glibc 2.34 moved libpthread, libdl, librt, libutil and libanl symbols
  into libc.so.6, keeping their old versions there. An import bound to
  such an old version, such as `pthread_key_create@GLIBC_2.17`, names its
  original library, here libpthread.so.0. Before 2.34 the symbol is
  defined only there. glibc 2.34 and later keep that library as a stub
  with the same version nodes, so the import resolves to libc.so.6. Bao
  applies this to a fixed list of the 210 symbols concerned, taken from
  glibc 2.33. It also applies when a shared-object input requires such a
  version.
- An import the inputs declare weak, such as an optional `getentropy` or
  `sem_clockwait`, is listed too. [Weak references](#weak-references) says
  when a target may lack it.
- Some symbols have no older version because they were never exported
  before. For example, `stat64`, `fstat64` and `lstat64` became libc exports
  in glibc 2.33. Before that they were static wrappers in
  `libc_nonshared.a` around `__xstat64`, `__fxstat64` and `__lxstat64`. An
  input built against glibc 2.33 or later imports `@GLIBC_2.33`, and no cap
  can move it older. To keep an older floor, define the wrappers yourself in
  the inputs, calling the `__*xstat64` functions with the version argument
  that glibc's pre-2.33 headers define as `_STAT_VER` for the target.

### Weak references

A weak reference that no sysroot library defines reads as NULL, and
`unavailable_weak_symbols` in bao-manifest.json lists it; a missing strong
import is rejected. On amd64 that covers loads, calls and comparisons through
its GOT slot, including `cmpq $0, sym@GOTPCREL(%rip)`, whose immediate after the
displacement biases the relocation by -5, as in zstd's optional trace hooks.
Other uses are refused with the symbol, section and offset. A weak import that
the sysroot defines may still be missing on an older target. It is optional
only if the code checks it before calling it. Where Bao binds it at package
initialization, a target that lacks it gives 0, as the dynamic linker would.
That covers every import of a shared-object input and pointers to it in an
archive's data. An archive's code references, such as calls and GOT loads, are
left to Go's linker. Go's linker cannot record a weak dynamic import, so the
target must define those symbols or the executable fails to start.

## Code and data

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

Common symbols, which a partial link leaves unallocated, get zero-filled space
in one `.bss.bao.common` section, with each symbol's size, alignment, binding
and visibility, as a final link allocates them. They come from assembler
`.comm` directives, such as OpenSSL's hidden `OPENSSL_ia32cap_P`, or from C
tentative definitions built with `-fcommon`.

Conditional and test-bit branches (`R_AARCH64_CONDBR19`,
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
build with `-mno-outline-atomics`. Other glibc/toolchain combinations need
separate verification.
The [example README](../examples/linux_runtime/README.md) records the final
pthread-destructor-pass boundary and process-lifetime libc bookkeeping after
explicit main-thread finalization.
`translate-elf` remains a compatibility alias; the `pack` and `probe-*`
commands remain available for low-level diagnostics.

## Thread-local storage

TLS initializers may hold absolute pointers to image data or system imports,
such as mimalloc's `__thread mi_heap_t *_mi_heap_default = &_mi_heap_empty`.
Bao writes them into its native TLS template before any thread copies it. A
pointer to another TLS variable, or any other relocation in a TLS template,
is rejected. This applies to every Linux target; it has run natively only on
arm64.

### amd64 TLS

The amd64 TLS profile accepts general/local dynamic TLS with ordinary SysV
`__tls_get_addr` calls and GNU2 TLSDESC (`-mtls-dialect=gnu2`), including
local-dynamic `_TLS_MODULE_BASE_` sequences. TLSDESC calls enter a Bao thunk.
When the calling thread's block is in the lookup table described under
[TLS lookup](#tls-lookup), the thunk clobbers only the flags, as
glibc's own descriptor resolvers may. Otherwise it preserves the other
general registers, flags, x87/MXCSR and XSAVE AVX/AVX-512 state while the C
lookup runs. TLSDESC output has run only under QEMU, with AVX2 and SSE-only CPU
models; AVX-512 preservation is unverified. Initial/local exec TLS (`R_X86_64_GOTTPOFF`, `R_X86_64_TPOFF32`)
is rejected: it assumes the image's TLS sits at a fixed offset from the
thread pointer, which Bao's per-thread blocks cannot provide.

### TLS lookup

Each thread's native TLS block is allocated on its first TLS access. Bao then
records it in a process-wide table indexed by a hash of the thread pointer. A
TLS access that finds the calling thread's entry costs a few loads, with no
call and no `pthread_getspecific`. On arm64 and amd64 the TLSDESC thunk then
saves three scratch registers instead of the full register and vector state.
Threads whose hashes collide share a table slot and take the slower path in
turn; that is still correct, only slower. Entries are removed when a thread's
TLS is finalized. A forked child removes every entry but the forking thread's,
because glibc may give a new thread in the child a dead thread's stack and so
its thread pointer. As before, the child does not reclaim those threads' TLS
blocks.

### Static TLS

`-linux-static-tls` (config key `linux.static_tls`) goes further: the image's
TLS moves into glibc's static TLS, at one constant offset from every thread
pointer, as for a library linked at startup. A TLS descriptor then resolves
with a single load (`ldr x0, [x0, #8]` or `movq 8(%rax), %rax`), and a
`__tls_get_addr` call adds that offset to the thread pointer. During package
initialization, after the template's pointer fixups, the generated package:

1. writes a small shared object to a memfd. Its PT_TLS segment is the
   template, and its one relocation is an initial-exec reference to its own
   TLS.
2. dlopens it through `/proc/self/fd`. glibc must then place it in static
   TLS, copying the template into every existing and future thread, or
   refuse it.
3. repoints the image's TLS descriptors at the constant resolver.

glibc looks up a dlopen path among already loaded objects' names before it
opens the file. So the memfd stays open for the life of the process, one
file descriptor, and no later memfd gets its number and with it this
module. If an object with that name is already loaded, the package does
not use static TLS.

glibc's spare static TLS is small. On glibc 2.41 a 1664-byte template fits by
default and a 1728-byte one does not, on both arm64 and amd64. That space is
shared with other libraries loaded later that use initial-exec TLS. It also requires
the template's alignment to be no larger than its static TLS alignment, 64
bytes on arm64. If memfd_create, /proc or the dlopen fails, the package keeps
Bao's per-thread blocks, as without the flag. `TLSStatic()` reports which
mode is in use. `GLIBC_TUNABLES=glibc.rtld.optional_static_tls=N` raises the
spare space at process start.

Because the space is shared, the flag is opt-in: a library dlopened later
that needs static TLS can fail to load once Bao has used it. With static TLS,
glibc owns each thread's block. `TLSLiveBlocks` and `TLSDestroyedBlocks`
then count only threads that registered native thread-exit destructors, such
as C++ `thread_local` objects or Rust TLS with destructors. Finalizing a
thread runs its destructors and restores the template's values in place,
just as a new block would start with them.

## Shared objects

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

`-wrap SYMBOL` applies to the library's imports too. The library's import of
`SYMBOL` binds to the input's `__wrap_SYMBOL`, through its GOT and PLT slots.
The input's `__real_SYMBOL` binds to the system symbol, with the version the
library was linked against. A dynamic link cannot do this: whatever
`--wrap` did, ld.so resolves the library's imports by name at run time. Bao
can because it links the library's image into the package.

- Only imports move. The library's calls to functions it defines itself do
  not.
- An import of `__wrap_SYMBOL` that the library already has binds to the same
  wrapper.
- Refused: a wrapped symbol that the library imports but the input does not
  wrap, and a library that defines `__wrap_SYMBOL` itself.

For example, glue that runs the library's threads on its own scheduler:

```sh
bao build -target linux/arm64 -sysroot / -symbol glue_run \
  -wrap pthread_create -wrap pthread_join \
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

## Implementation notes

Bao lowers compiler TLS sequences (TLSDESC, and `__tls_get_addr` calls on amd64,
loong64 and ppc64le) to image-private descriptors and a resolver that returns
offsets relative to the native thread pointer. Per-thread blocks use native
pthread storage and destructors and are found through the table described under
[TLS lookup](#tls-lookup), or live in glibc's static TLS with
`-linux-static-tls`. Native DWARF chains are registered with libgcc's `__register_frame`.
Initializers run in numeric priority order with native copies of argv and libc's environ.
Imported data pointers are fixed up in writable native storage before constructors.
