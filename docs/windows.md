# Windows targets

Reference for producing packages for windows/amd64 and windows/arm64.
[Platform support](../README.md#platform-support) lists where each target has run.

## Producer reference

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
See [bundling language runtimes](../README.md#bundling-language-runtimes) for C++
archives and [examples/windows_std](../examples/windows_std) for the complete std
fixture. The smaller `examples/windows_runtime` Rust crate uses `no_std`.

COFF weak aliases, common symbols and COMDAT selection are supported, including
`ANY`, `NODUPLICATES`, `SAME_SIZE`, `EXACT_MATCH`, `LARGEST`, `NEWEST` and
`ASSOCIATIVE`. Conflicting/malformed selection metadata is rejected. Ordinary
data alignment is limited to 32 bytes and code alignment to 16 bytes. TLS supports
alignment up to 8192 bytes and a 64 MiB template; unrecognized access forms and
TLS template relocations are rejected. Managed FLS keys must stay within the
image; destructor re-registration is bounded to four rounds. Native lifecycle
callbacks must not throw. Bigobj inputs (which `bao objcopy` can still edit),
ARM64EC and MSVC Rust targets remain unsupported.
Debug stripping retains runtime unwind metadata.

## DLL input

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
- Loading the DLL's own dependencies from inside the image: imports use the
  ordinary `LoadLibrary` search.

`DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` are not delivered, and the DLL has
no module handle: `GetModuleHandle` and `GetModuleFileName` do not know it, and
its `DllMain` receives its base as `HINSTANCE`.

### Relocatable code with a DLL

To add relocatable code that calls the DLL, such as glue for an embedded
interpreter, pass that code as the input and the DLL with `-windows-dll`
(config key `windows.dll`). The input, an object or archive, is translated as
usual. References that no input member defines then bind to the DLL's
exports, as a static link against its import library would. They take
precedence over the built-in import catalog and `-windows-import-library`,
but not over `-windows-import`.

```sh
bao build -target windows/amd64 -symbol glue_run \
  -windows-dll python313.dll -o ./py glue.obj
```

- The input reaches the DLL's exports through private import cells, filled
  as soon as the DLL is loaded and before its `DllMain` runs. Calls work as
  direct calls or through `__imp_`. Data needs a `__declspec(dllimport)`
  declaration, the `__imp_` form.
- `-symbol` selects the input's functions, then functions the DLL exports.
  `SharedObjectExport(name)` and `SharedObjectExports()` cover the DLL's
  exports, as for DLL input.
- The input's thread-local variables follow the DLL's in Bao's TLS template.
  The DLL's stay at the offsets its code uses.
- Order at initialization: the DLL loads and its `DllMain` runs, then the
  input's initializers.
- The input's TLS callbacks receive the DLL's base as their module, like the
  DLL's own.

`-wrap SYMBOL` applies to the DLL's imports too. The DLL's import of `SYMBOL`
resolves to the input's `__wrap_SYMBOL`, and the input's `__real_SYMBOL` binds
to the system DLL. Only imports by name move; the DLL's calls to functions it
defines itself do not. A wrapped symbol that the DLL imports but the input
does not define as `__wrap_SYMBOL` is refused.

```sh
bao build -target windows/amd64 -symbol glue_run \
  -wrap CreateThread -windows-dll python313.dll -o ./py glue.obj
```

## Implementation notes

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
and MSVC static/debug CRTs remain outside that profile. Native Windows VM CI is
configured for VC++, Clang and clang-cl on both architectures and MinGW on
amd64; its results are pending, and Wine is a local aid only. See
[Windows producer commands and boundaries](#producer-reference)
for the complete profile, compiler flags and verification scope.
