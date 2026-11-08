# Optimized DWARF compiler fixtures

The authored C, C++ and Rust sources here are Apache-2.0. Their small compiler
object products are test inputs, not linked runtime support. Unit tests need
only Go. `provenance.json` records source/object SHA-256 values, compiler
versions and command arguments; fixture changes require regenerating those
products and their provenance.

All positive objects use optimization and full source-level debug information:
Apple clang/clang++ 21 with `-O2 -gdwarf-4` for Mach-O, GCC/G++ 14.2 with the
same options for Linux arm64 ELF, and Rust 1.99.1 with `-O -g` for both. Native
types and parameter order remain recoverable even when parameter locations are
optimized away. The C inline function and C++ static-method declaration produce
real abstract-origin/specification chains. Linux GCC also folds identical
function bodies and emits only a typed abstract/declaration record for one
export; external object symbol definitions disambiguate it.

`c_no_debug_elf.bin` keeps normal runtime unwind metadata but has no source
DWARF. It must not infer function signatures. `cc_macho.bin` uses the Win64
calling convention on an x86-64 Mach-O input and must be rejected. Other
negative controls cover callbacks, aggregates by value, varargs, unsupported
boolean encoding, missing exports, duplicate archive definitions, conflicting
origins and cyclic debug references. C++ lvalue references and Rust references
normalize to native pointers, while callback-pointer chains are rejected.

Inference reads original object/archive bytes before Bao strips native debug
sections. Selected exports are still an explicit assertion of C ABI: ordinary
DWARF does not reliably prove that Rust functions were declared `extern "C"`.
Split/external debug files, DWARF type-signature references, dynamic types,
aggregates/varargs/callback support and missing full type information require an
explicit supported manifest or are rejected. No debug companion or source file
is opened while inferring. The producer's public type selection is intentionally
more conservative than everything DWARF can describe.
