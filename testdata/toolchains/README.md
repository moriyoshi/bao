# Linux cross verification image

GCC/Clang C++ images for Linux arm64 and amd64 use separate pinned Dockerfiles;
see the [C++ build and verification recipe](../../examples/cpp_linux/README.md).
Those suites do not require this Rust cross image.

Build the maintainer image once with network access:

```sh
docker build -f testdata/toolchains/linux-cross.Dockerfile -t bao-linux-cross:20261108 .
```

The Dockerfile pins the ARM64 Rust 1.99.1 base digest, a dated Debian snapshot,
and top-level native tool packages, including matching GCC 14.2 cross C++
compilers and Clang 19.1.7. Preserve the resulting image digest with release evidence.
Rust target downloads occur only while preparing the image. The integration
suite itself uses `--pull=never`, `--network=none` and a read-only execution
filesystem. Its Go dependency setup fetches checksum-verified purego v0.11.3;
consumer builds then disable module networking and native compilers.

```sh
bazelisk run //:verify -- -suite linux-cross -target linux/loong64 \
  -image bao-linux-cross:20261108 -evidence .work/linux-loong64-new
bazelisk run //:verify -- -suite linux-cross -target linux/ppc64le \
  -image bao-linux-cross:20261108 -evidence .work/linux-ppc64le-new
```

These are actual LoongArch64 and PowerPC64LE ELF guest executions under QEMU
10.0.13 on a Linux ARM64 container host. They do not establish physical target
hardware support. The standalone Rust library includes standard-library panic
unwinding, pthread cleanup/TLS state, eight native Rust threads, native and TLS
alignment, constructors, imported data, allocation and a libc-to-Rust callback.
Removing only FDE registration must preserve linking and cause the panic to
abort. All retained native section alignments and absence of RWX ELF PT_LOAD
segments are audited.

The PowerPC suite also checks all 64 complete 128-bit VSX registers and R2
through local and global ELFv2 resolver entries. A valid simulated C-callee
volatile FP clobber must survive the TLS preservation thunk; removing one
register restoration must still link and fail at execution. The thunk also
preserves FPSCR, VSCR, VRSAVE, CR and XER. LLVM's
[PowerPC TLS call definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/PowerPC/PPCInstr64Bit.td)
explain why floating/vector preservation is stricter than an ordinary C call.

Both profiles require little-endian ELF64/glibc and the checked GD/LD TLS forms.
PowerPC requires the ELFv2 ABI; ELFv1/function descriptors are rejected. Other
TLS models, TLS-template relocations, arbitrary shared-library load/unload,
cross-image destructor interleaving, preinit/fini arrays and native IFUNC
definitions remain unsupported or unverified, as do the common Linux runtime
limitations described in `examples/linux_runtime/README.md`.

The [C++ cross recipe](../../examples/cpp_linux/README.md) runs the Rust runtime
and typed-binding gates first, then both GCC/libstdc++ and Clang/libstdc++
C++ lifecycle suites in this same image. Source CI and the reusable release CI gate require all of
them; a C++ result alone does not establish Rust compatibility.

LoongArch CALL36 instruction pairs are lowered to B26 plus a retained NOP slot
to avoid a backward-call encoding bug in the pinned stock Go linker. This
preserves native instruction addresses and unwind/call-site ranges. LoongArch
LSDA ULEB differences are folded only when both symbols share a section. Native
PC-relative unwind data unsupported by Go's relocation implementation is
initialized in writable native metadata before FDE registration; executable
pages are never patched at runtime.
