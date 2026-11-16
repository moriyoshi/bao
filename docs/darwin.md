# Darwin targets

Reference for producing packages for darwin/arm64 and darwin/amd64.
[Platform support](../README.md#platform-support) lists where each target has run.

## Object and archive input

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
ObjC/Swift image metadata or class registration in object input (a
[dylib input](#dylib-input) registers it), indirect/stub sections,
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
table bytes remain in place.

## Dylib input

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
  `LC_DYLD_INFO` rebase and bind opcodes; lazy binds are bound eagerly. Only
  stub helpers use `dyld_stub_binder`, which `dlsym` does not find on macOS
  26, so its bind is dropped. Each bind resolves in the library its two-level
  namespace names, opened with `dlopen` by its install name. A missing weak
  import is null.
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
  initializers. Categories on other images' classes work, and their instance
  and class properties are attached with `class_replaceProperty`.
- **Swift:** the loader passes the image's protocol, conformance and type
  records (`__swift5_protos`, `__swift5_proto`, `__swift5_types`) to
  libswiftCore's `swift_registerProtocols`,
  `swift_registerProtocolConformances` and `swift_registerTypeMetadataRecords`,
  after the Objective-C step (Swift classes are Objective-C classes there).
  Dynamic casts to protocols, generics, enums, errors, actors, NSObject
  subclasses with `@objc` members, and subclasses of classes from resilient
  frameworks (Objective-C class stubs) work. Automatic dynamic replacements
  (`@_dynamicReplacement`, `__swift5_replace`) are enabled with
  `swift_enableDynamicReplacementScope`, including replacements of functions in
  other images. Replacements of functions with opaque result types
  (`__swift5_replac2`) and distributed actors' accessible functions
  (`__swift5_acfuncs`) are rejected: libswiftCore registers them only from
  dyld's image callback. Runtime lookups that scan every image's reflection
  sections by name do not see this one.
- **Exports:** `SharedObjectExport(name)`, `SharedObjectExports()` and
  `-symbol` accessors return the image's addresses.

Not supported:
- arm64e dylibs, and tagged or multi-start chained fixups.

`dladdr` reports the executable for the dylib's code, `__mod_term_func` does not
run, and weak definitions are not coalesced across images. Making the
`__TEXT` data pages writable has run only without the hardened runtime.

### Relocatable code with a dylib

To add relocatable code that calls the dylib, such as glue for an embedded
interpreter, pass that code as the input and the dylib with `-darwin-dylib`
(config key `darwin.dylib`). The input is combined as usual. Its undefined
references to the dylib's exports then bind to the image, as a static link
against the dylib would, and its other references bind to the SDK as usual.

```sh
bao build -target darwin/arm64 -symbol glue_run \
  -darwin-dylib libpython3.13.dylib -o ./py glue.o
```

- The image is a section of the translated input, so these references are
  ordinary relocations: no import, no `dlsym`, and no Apple linker. A
  producer on Linux needs only `-sdk`, and a single object needs no partial
  link.
- `-symbol` selects the input's exports, then functions the dylib exports.
  `SharedObjectExport(name)` and `SharedObjectExports()` cover the dylib's
  exports, as for dylib input.
- The input's thread-local variables use the same TLS runtime as the dylib's.
  Each thread's block holds the input's template, then the dylib's, and the
  loader moves the dylib's descriptor offsets past the input's. The input's
  template must not hold addresses, as for object input. Key destructors see
  them as described in
  [Thread-local variables at thread exit](#thread-local-variables-at-thread-exit).
- The dylib's initializers run before the input's.

`-wrap SYMBOL` applies to the dylib's binds too. The dylib's bind of `SYMBOL`
resolves to the input's `__wrap_SYMBOL`, and the input's `__real_SYMBOL` binds
to the system symbol. Only binds move; the dylib's calls to functions it
defines itself do not. A wrapped symbol that the dylib binds but the input
does not define as `__wrap_SYMBOL` is refused.

```sh
bao build -target darwin/arm64 -symbol glue_run \
  -wrap pthread_create -wrap pthread_join \
  -darwin-dylib libpython3.13.dylib -o ./py glue.o
```

Python extension modules that libpython loads with `dlopen`, such as
python-build-standalone's `_dbm` and `_tkinter`, are not expected to find its
symbols, since dyld never loaded the dylib. This is unverified.

## Thread-local variables at thread exit

Bao's TLS runtime keeps each thread's block under one pthread key per
generated package, created at package initialization. This covers object
input, a dylib, and an object with a dylib. At thread exit, that key's
destructor runs the thread's `thread_local` destructors, then frees the block.

Pthread keys that native code creates after that can have their destructors
run after Bao's. A thread-local access from such a destructor gets a new block
initialized from the template, so the variable reads as its initial value,
such as zero or NULL. That block is freed in a later destructor round. Pass a
value that a key destructor needs through the key's own value
(`pthread_setspecific`), not through a thread-local variable.

This matches native macOS: with dyld's thread-local variables, the same C
code also read the initial value in its key destructor.

## Implementation notes

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
