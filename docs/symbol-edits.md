# Symbol edits

`bao build` can rename symbols in its Linux ELF, macOS Mach-O and Windows COFF
inputs before they are combined, so a producer needs neither `objcopy` nor a
second relinking step. The same edits are available on single files as
`bao objcopy`. Supported inputs are ELF relocatable objects of either class
and byte order,
64- and 32-bit little-endian Mach-O objects and universal (fat) files of them,
amd64/arm64 COFF relocatable objects (regular or bigobj), and archives of all
of these. Import library members pass through unchanged (see the COFF notes).

`bao objcopy` also handles formats that `bao build` does not translate:

- ELF32 and big-endian ELF objects, such as i386, armv7, powerpc, mips,
  s390x and aarch64_be. They are edited through an equivalent little-endian
  ELF64 copy, and every byte the edit does not change keeps its offset.
  MIPS64, whose relocations pack several types into `r_info`, and CREL
  relocations in ELF32 objects are refused.
- COFF bigobj, which `cl /bigobj` and `-Wa,-mbig-obj` write, and which LLVM
  writes for more than 65279 sections. `bao build` says so when given one.
- Universal Mach-O files, objects or archives. Each slice is edited as if it
  were alone, and the result keeps the architectures, their order and their
  alignments, in FAT_MAGIC or FAT_MAGIC_64.
- 32-bit Mach-O objects (i386, armv7). Their scattered relocations name an
  address. A symbol at such an address counts as referenced, and its section
  cannot be removed.
  - A 32-bit ARM alias made with `@SYMBOL:0` keeps a Thumb function's
    `N_ARM_THUMB_DEF`.
  - 32-bit code also reaches local functions through section-relative
    relocations, and each defined symbol starts an atom. So
    `-strip-unneeded` keeps 32-bit section symbols, because `ld -r` fails on
    an atom left without one.

## Renames

Names are C names on both formats, as for `-symbol`. On Mach-O, Bao matches and
writes them with the leading underscore that C symbols carry, so
`-wrap pthread_create` edits `_pthread_create`. Mach-O symbols without that
underscore, such as assembler labels, are never edited.

| Flag | Effect |
| --- | --- |
| `-wrap SYM` | References to `SYM` go to `__wrap_SYM`, and undefined `__real_SYM` becomes `SYM`, with `ld.lld --wrap` semantics |
| `-redefine-sym OLD=NEW` | Rename every `OLD` symbol, defined or undefined, as `llvm-objcopy --redefine-sym` |
| `-redefine-syms FILE` | Rename from `OLD NEW` lines; `#` starts a comment, as `llvm-objcopy --redefine-syms` |
| `-prefix-symbols PATH=PREFIX` | Prefix the symbols that the input or `-link-archive` at `PATH` defines (build only) |

All flags are repeatable. `-wrap` and `-redefine-sym(s)` apply to the input and
every `-link-archive`, so wrapper glue can live in any of them. Each edit applies
to input names; a renamed symbol is not edited again.

`-wrap` follows lld rather than GNU ld: when an object both defines and calls
`SYM`, that call also goes to `__wrap_SYM`. Bao adds an undefined `__wrap_SYM`
to that object and redirects its runtime relocations. Relocations in debug
sections keep describing the definition. Relocations in LLVM's CREL format
(`-Wa,--crel`) are decoded, edited like RELA ones, and encoded again as LLVM
encodes them when they change.

`-prefix-symbols` makes a component's definitions private. Only symbols
defined in that component, and that component's references to them, gain the
prefix. Other undefined references, such as `malloc` or a `Py*` function from
another input, keep their names. Inputs that share a prefix form one component,
so a vendored library and the extension that calls it can share one prefix. A
wrapped or explicitly renamed symbol is not prefixed. An identity rename such as
`-redefine-sym PyInit_mod=PyInit_mod` keeps an entry point's name.
`PATH` must name the same file as the input or a `-link-archive`.

```sh
# libext1.a calls its vendored libssl.a. Both share one prefix, and the
# identity rename keeps the entry point that libapp.a calls.
bao build -target linux/arm64 -symbol app_main \
  -wrap pthread_create -wrap recv \
  -link-archive ext1/libext1.a -link-archive ext1/libssl.a \
  -prefix-symbols ext1/libext1.a=ext1_ -prefix-symbols ext1/libssl.a=ext1_ \
  -redefine-sym PyInit_ext1=PyInit_ext1 \
  -o ./native libapp.a
```

Edits apply to Bao's private copies of the inputs. Symbol and section bytes
other than the edited names, symbols and relocations are preserved. An edited
archive is rewritten with a new symbol index, because a searched archive's index
must name the renamed definitions. ELF archives use GNU format. Mach-O archives
use the BSD format of Apple's `ar`, with a `__.SYMDEF` index and 8-byte-aligned
members. `bao-build.json` records the
edits under `symbol_edits`. Its source and link-archive digests stay those of
the unedited files. `-bindings dwarf` reads the unedited input, so name renamed
exports with a signature manifest instead.

```sh
bao objcopy -wrap pthread_create -redefine-syms renames.txt libpython.o libpython-edited.o
bao objcopy -prefix-symbols ext1_ libvendor.a libvendor-private.a
```

`bao objcopy` takes one input and a new output, which must not exist.
`-prefix-symbols PREFIX` there prefixes the input's own definitions.

## Symbol bindings and stripping

These flags hide or remove symbols, as the llvm-objcopy flags of the same
names do. In `bao build` each one names its component first, as `PATH=SYMBOL`,
`PATH=FILE` or `PATH`. In `bao objcopy` it applies to the one input, so it
takes only `SYMBOL` or `FILE`, or nothing.

| Flag | Effect |
| --- | --- |
| `-localize-symbol SYM` | Make that definition local |
| `-localize-symbols FILE` | `-localize-symbol` for each line of `FILE` |
| `-localize-hidden` | Make hidden and internal definitions local |
| `-keep-global-symbol SYM` | Keep `SYM` global and make every other definition local |
| `-keep-global-symbols FILE` | `-keep-global-symbol` for each line of `FILE` |
| `-globalize-symbol SYM` | Make that definition global |
| `-weaken-symbol SYM` | Make that global symbol weak, defined or undefined |
| `-strip-symbol SYM` | Remove that symbol; it is an error if a relocation or section group names it |
| `-strip-unneeded` | Remove local and undefined symbols that no relocation or section group names |
| `-wildcard` | Treat the names above as shell patterns; a pattern starting with `!` excludes names |

Bindings change in llvm-objcopy's order: localize, then keep-global, then
globalize, then weaken. Removal comes after that. Names match input names, as
for the renames. Undefined and common symbols are never made local.
`-strip-unneeded` keeps section symbols and ARM/AArch64/RISC-V mapping symbols
such as `$x`. Unlike llvm-objcopy, it does not remove debug sections;
`-strip-debug` does that after binding inference.
Local symbols must precede the others in ELF. Bao therefore rewrites the symbol
table and renumbers every relocation, section group, extended section index
and LLVM address-significance entry, in REL, RELA and CREL relocation
sections. It rejects any other section that refers to symbol indices.

`-wrap` applies to every input of the link. `-keep-global-symbol` and
`-localize-hidden` therefore leave a wrapped symbol's definition and its
`__wrap_` wrapper global, so the other inputs' wrapped references still
resolve. Naming one with `-localize-symbol` still hides it.

On Mach-O, a private extern (`N_PEXT`, from hidden visibility) counts as
hidden. Localizing clears its external bits. Weakening sets `N_WEAK_DEF` on a
definition or `N_WEAK_REF` on an import. Symbols marked no-dead-strip (from
`__attribute__((used))`) or `REFERENCED_DYNAMICALLY` count as needed:
`-strip-unneeded` keeps them, and `-strip-symbol` refuses them. Every Mach-O
edit rewrites the symbol table in the order ld64 expects: locals in input
order, then external definitions and imports, each sorted by name. It then
renumbers extern relocations and the indirect symbol table. A wrapped
definition's references in debug sections, `__LD,__compact_unwind` and
`__eh_frame` keep naming the definition. An undefined `__real_SYM` beside a
defined `SYM` in one object is bound directly to it and removed.

On COFF, names need no underscore on amd64 and arm64. A `dllimport` caller's
`__imp_SYM` follows its function: `-wrap SYM` turns it into
`__imp___wrap_SYM`, and a rename renames it. COFF has no ordering between
local and global symbols, so binding changes edit the storage class in place.
Removing symbols renumbers relocations, weak-external tags and
`.llvm_addrsig`. Rules specific to COFF:

- COFF has no hidden visibility, so `-localize-hidden` matches nothing.
- `-weaken-symbol` writes clang's weak encoding. Each symbol becomes a weak
  external with `IMAGE_WEAK_EXTERN_SEARCH_ALIAS` and a default named
  `.weak.NAME.default.SUFFIX`. SUFFIX is the object's first strong external
  definition, as in LLVM.
  - A weakened definition is renamed to its default in place, so a `/Gy`
    COMDAT key stays its section's key.
  - Code refers to the weak external, so a strong definition elsewhere wins
    for the object's own calls too. Unwind and debug data keep naming the
    default.
  - A weakened reference gets an absolute zero default.
  - The archive index lists a weakened definition under its name, but not a
    weakened reference. Indexing that would let the linker pull its member
    instead of the one with the strong definition.
  - A COMDAT key whose selection already merges copies is left as it is.
    Weakening a common symbol is refused.
  - As with `-wrap`, a call that the assembler resolved inside one section
    has no relocation and keeps the default. Compile with
    `-ffunction-sections` or `/Gy`. MinGW GCC calls same-object functions
    through their section even then.
- A COMDAT section's key symbol is never stripped, even by `-strip-unneeded`.
  Neither are section definitions or `@feat.00`.
- A wrap does not redirect debug sections, `.pdata` or `.xdata`.
- Calls within one section usually carry no relocation, so a wrap cannot
  redirect them, as with lld-link. Compile with `-ffunction-sections` or
  `/Gy` to keep them redirectable. GNU as for PE (MinGW GCC) refers to a
  function defined in the same object through its section even then. Such
  objects therefore get GNU ld's wrap semantics: only references through
  the symbol move.
- `.drectve` directives follow renames from `-redefine-sym` and
  `-prefix-symbols`; a wrap leaves them alone. An `-exclude-symbols` entry
  for a symbol that is no longer exported is dropped. An `/INCLUDE` or
  `/ALTERNATENAME` of one is an error.
- Bao selects Windows archive members itself, without a partial linker. A
  Windows primary archive's binding edits are therefore applied member by
  member, like a `-link-archive`.
- Import library members, both short import declarations and the descriptor
  and thunk objects with `.idata` sections, pass through unchanged and stay in
  the archive index. A DLL import's name is also the export it binds to, so
  `-prefix-symbols` leaves imports alone; references to them keep their names.
  A wrap applies to the references in other members, and `-keep-global-symbol`
  and the other flags that act on every definition skip imports. A flag that
  names an import, such as `-redefine-sym malloc=my_malloc` or
  `-localize-symbol __imp_malloc`, is an error.
- Edited COFF archives use the Microsoft library format: two linker members
  and NUL-terminated long names.

A hidden symbol usually links the members of one archive together, so
localizing it in each member separately breaks the archive. When the build's
input is an archive with binding or strip flags, Bao first partially links it
on its own with the native `ld -r`. It then edits the single object, and
`bao-build.json` records `combined_first`. A `-link-archive` is searched, so its
members are edited separately. So is any archive given to `bao objcopy`. That is
an error when one member refers to a definition that another member no longer
exports; use `-prefix-symbols` for such an archive.

```sh
# Keep only the Python C API and pythago's glue global in libpython.a. Its
# vendored expat and HACL* symbols then cannot collide with a wheel's copies.
bao build -target linux/arm64 -symbol pythago_main -wildcard \
  -keep-global-symbol 'libpython.a=Py*' -keep-global-symbol 'libpython.a=_Py*' \
  -keep-global-symbol 'libpython.a=pythago_*' -strip-unneeded libpython.a \
  -link-archive wheels/libext1.a -o ./native libpython.a

bao objcopy -localize-hidden -strip-unneeded libpython.o libpython-private.o
```

## Section edits

These flags remove sections or add symbols, as the llvm-objcopy flags of the
same names do, in ELF, Mach-O and COFF objects. In `bao build` each names its
component first, as for the binding flags.

| Flag | Effect |
| --- | --- |
| `-remove-section SECTION` | Remove the section, its relocations and the symbols defined in it |
| `-only-section SECTION` | Keep only matching sections, with their relocations; ELF also keeps groups and the symbol, string and section name tables |
| `-add-symbol NAME=[SECTION:]VALUE[,FLAGS]` | Add a symbol at an offset in a section, or an absolute one without a section |
| `-add-symbol NAME=@SYMBOL:OFFSET[,FLAGS]` | Add a symbol OFFSET bytes past a definition, in its section (a Bao extension) |

Mach-O sections are named `SEGMENT,SECTION`, such as `__TEXT,__text`, as
llvm-objcopy names them. `-wildcard` makes section names shell patterns too.
`-add-symbol` flags are `global` (the default), `local`, `weak`, `default`,
`hidden`, `protected`, `object`, `function` and `notype`. Adding a name the
object already defines is an error. In an archive, a symbol is added to each
member that has its section, and two members defining it is an error.

`@SYMBOL` names the definition by its input C name: the only global one, or
else the only local one. More than one is an error. The alias takes the
target's section, or is absolute when the target is, so no section name is
needed. That covers COFF objects whose COMDAT sections share a name. It also
covers a Darwin primary archive that `ld -r` merges into one `__TEXT,__text`.

On ELF, removal renumbers every section index: symbol sections, the extended
index table, links, relocation targets, group members and the section name
table index. A section group goes when its last member does. On Mach-O and
COFF, the removed sections' headers leave the segment command or section
table, and symbol and relocation section numbers are renumbered. Their
contents stay in the file, unreferenced, so no other offset moves. The edit
is refused in these cases:

- A kept relocation or section group names a symbol defined in a removed
  section. That includes an ELF or COFF section symbol, which unwind and
  debug data usually name, as llvm-objcopy also refuses.
- A kept Mach-O section-relative relocation names a removed section.
  `__compact_unwind` and DWARF use these for `__text`. llvm-objcopy drops such
  relocations instead, which leaves those entries unrelocated.
- A kept ELF section links to a removed one.
- A removal targets the ELF symbol, string or section name table.

Unlike llvm-objcopy, `-only-section` keeps the relocations of the ELF sections
it keeps, so the result still links.

Format notes:

- Mach-O data-in-code entries and linker optimization hints for addresses in
  removed sections are dropped.
- A removed Mach-O symbol pointer or stub section takes its run of the
  indirect symbol table with it. The later sections' `reserved1` moves down,
  and the run's symbols no longer count as referenced. llvm-objcopy leaves the
  entries in the table, unreferenced. Apple's current `ld` rejects such
  sections in 64-bit objects anyway ("non-lazy pointers sections no longer
  supported"), so this matters for 32-bit objects.
- A COFF associative COMDAT section, such as the `.pdata` and `.xdata` of an
  MSVC-environment function section, goes with the section it is associated
  with, as in llvm-objcopy. MinGW function sections such as `.text$f` keep
  their unwind data in COMDAT sections of their own, `.xdata$f` and
  `.pdata$f`; remove them together with `-wildcard -remove-section '*$f'`.
- A COFF `.llvm_addrsig` entry for a removed symbol is dropped. llvm-objcopy
  keeps it, with an index past the new symbol table.
- A Mach-O `-add-symbol` value is an offset in its section, as in ELF objects.
  `hidden` makes a private extern; Mach-O has no `protected` visibility and no
  symbol types.
- A COFF `-add-symbol` section name must be unique in the object. Several
  COMDAT sections often share one, such as `.text` with clang-cl (`/Gy-`
  avoids that) and `.text$mn` with `/Gy`; name a symbol with `@SYMBOL`
  instead. COFF has no symbol visibility, and
  its weak externals need a default definition, so `hidden`, `protected` and
  `weak` are refused. `function` sets the function type.
- On Mach-O and COFF, an undefined symbol of the added name becomes the
  definition, so the object's references bind to it. ELF adds a separate
  symbol, as llvm-objcopy does.
- `ld -r` merges a Darwin primary archive's sections when `bao build` combines
  it first, so section names then cover every member, and `ld -r` itself
  drops `__DWARF` sections.

```sh
# Export an alias at the start of a function's section, and drop .comment.
bao build -target linux/arm64 -symbol app_main -symbol app_entry_alias \
  -add-symbol 'libapp.a=app_entry_alias=.text.app_main:0,function' \
  -remove-section libapp.a=.comment -o ./native libapp.a

# Drop Mach-O debug data and alias the function at the start of __text.
bao objcopy -wildcard -remove-section '__DWARF,*' \
  -add-symbol 'app_alias=__TEXT,__text:0,function' app.o app-nodebug.o

# Alias a function wherever it is, in any format.
bao objcopy -add-symbol 'app_entry_alias=@app_main:0,function' app.obj app-alias.obj
```
