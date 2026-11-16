package linuxelf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// StaticTLSModule is the start of a minimal ELF shared object whose PT_TLS
// segment is an image's TLS template. The generated package appends the
// template, after its pointer fixups, and dlopens the result from a memfd.
// The object's one relocation is a thread-pointer-relative (initial-exec)
// reference to its own TLS, so glibc must place the module in static TLS or
// refuse it; once loaded, the relocated word holds the constant offset of
// every thread's block from its thread pointer.
type StaticTLSModule struct {
	Prefix     []byte `json:"-"`           // ELF headers, padded to the template's alignment
	OffsetWord uint64 `json:"offset_word"` // module-relative address of the relocated word
}

var staticTLSMachines = map[string]struct {
	machine elf.Machine
	flags   uint32
	tprel   uint32
}{
	"arm64":   {elf.EM_AARCH64, 0, uint32(elf.R_AARCH64_TLS_TPREL64)},
	"amd64":   {elf.EM_X86_64, 0, uint32(elf.R_X86_64_TPOFF64)},
	"loong64": {elf.EM_LOONGARCH, 0x43, uint32(elf.R_LARCH_TLS_TPREL64)}, // LP64D, object ABI v1
	"ppc64le": {elf.EM_PPC64, 2, uint32(elf.R_PPC64_TPREL64)},            // ELFv2
}

// StaticTLSStub builds the module prefix for a template of size bytes and
// the given alignment on arch.
func StaticTLSStub(arch string, size, alignment uint64) (StaticTLSModule, error) {
	m, ok := staticTLSMachines[arch]
	if !ok {
		return StaticTLSModule{}, fmt.Errorf("static TLS is unsupported on %s", arch)
	}
	if size == 0 || alignment == 0 || alignment&(alignment-1) != 0 || alignment > 4096 {
		return StaticTLSModule{}, fmt.Errorf("static TLS needs a nonempty template aligned to a power of two up to 4096 bytes, not %d bytes aligned to %d", size, alignment)
	}
	const (
		ehdr    = 64
		phent   = 56
		phnum   = 4
		dynOff  = ehdr + phent*phnum
		dynNum  = 9
		symOff  = dynOff + 16*dynNum
		strOff  = symOff + 24
		relaOff = strOff + 8
		wordOff = relaOff + 24
		headers = wordOff + 8
	)
	template := (uint64(headers) + alignment - 1) &^ (alignment - 1)
	total := template + size
	b := make([]byte, template)
	le := binary.LittleEndian
	copy(b, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	le.PutUint16(b[16:], uint16(elf.ET_DYN))
	le.PutUint16(b[18:], uint16(m.machine))
	le.PutUint32(b[20:], uint32(elf.EV_CURRENT))
	le.PutUint64(b[32:], ehdr) // e_phoff
	le.PutUint32(b[48:], m.flags)
	le.PutUint16(b[52:], ehdr)
	le.PutUint16(b[54:], phent)
	le.PutUint16(b[56:], phnum)
	le.PutUint16(b[58:], 64) // e_shentsize; there are no sections
	phdr := func(i int, typ elf.ProgType, flags elf.ProgFlag, off, filesz, memsz, align uint64) {
		p := b[ehdr+i*phent:]
		le.PutUint32(p[0:], uint32(typ))
		le.PutUint32(p[4:], uint32(flags))
		le.PutUint64(p[8:], off)
		le.PutUint64(p[16:], off) // p_vaddr
		le.PutUint64(p[24:], off) // p_paddr
		le.PutUint64(p[32:], filesz)
		le.PutUint64(p[40:], memsz)
		le.PutUint64(p[48:], align)
	}
	phdr(0, elf.PT_LOAD, elf.PF_R|elf.PF_W, 0, total, total, 0x10000)
	phdr(1, elf.PT_DYNAMIC, elf.PF_R|elf.PF_W, dynOff, 16*dynNum, 16*dynNum, 8)
	phdr(2, elf.PT_TLS, elf.PF_R, template, size, size, alignment)
	// Without PT_GNU_STACK, glibc would treat the module as needing an
	// executable stack, which current releases refuse to dlopen.
	phdr(3, elf.PT_GNU_STACK, elf.PF_R|elf.PF_W, 0, 0, 0, 16)
	for i, d := range [dynNum][2]uint64{
		{uint64(elf.DT_SYMTAB), symOff},
		{uint64(elf.DT_STRTAB), strOff},
		{uint64(elf.DT_STRSZ), 1},
		{uint64(elf.DT_SYMENT), 24},
		{uint64(elf.DT_RELA), relaOff},
		{uint64(elf.DT_RELASZ), 24},
		{uint64(elf.DT_RELAENT), 24},
		{uint64(elf.DT_FLAGS), uint64(elf.DF_STATIC_TLS)},
		{uint64(elf.DT_NULL), 0},
	} {
		le.PutUint64(b[dynOff+16*i:], d[0])
		le.PutUint64(b[dynOff+16*i+8:], d[1])
	}
	// Symbol 0 is the null symbol; a TPREL relocation against it resolves
	// to this module's own TLS block plus the addend, as linkers emit for
	// local initial-exec references.
	le.PutUint64(b[relaOff:], wordOff)
	le.PutUint64(b[relaOff+8:], uint64(m.tprel))
	return StaticTLSModule{Prefix: b, OffsetWord: wordOff}, nil
}
