package linuxelf

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A linked PIC shared object reaches its own code, data and GOT through
// PC-relative instructions that no longer carry relocations, so its segments
// cannot be split into ordinary relocatable sections without disassembly.
// Bao instead carries the whole load image as one executable section, keeps
// its internal layout, and turns its dynamic relocations into link-time
// pointers, init-time import fixups and Bao TLS descriptors. Go's ELF loader
// rejects writable executable sections, so the generated package makes the
// writable segments read-write (and not executable) before native code runs.
//
// The section is 4 KiB-aligned: AArch64 ADRP arithmetic only needs the image
// offset preserved modulo 4 KiB, and stock Go's linker misplaces runtime.text
// when text requests more (see the 2026-11-14 text alignment journal entry).
// Pages that are made writable at run time must never hold executable code, so
// the largest supported page size is the smallest gap between a writable
// segment and executable code, capped at sharedObjectPad.

// SharedObject describes a shared object linked into the translated image.
type SharedObject struct {
	SONAME     string   `json:"soname,omitempty"`
	SHA256     string   `json:"sha256"`
	Needed     []string `json:"needed,omitempty"`
	BaseSymbol string   `json:"base_symbol"`
	// CheckOffset holds a link-time pointer to the image base. A PIE leaves
	// pointers in text unrelocated, which the generated package detects.
	CheckOffset uint64         `json:"base_check_offset"`
	ImageSize   uint64         `json:"image_size"`
	MaxPageSize uint64         `json:"max_page_size"`
	Writable    []Range        `json:"writable_ranges"`
	RELRO       []Range        `json:"relro_ranges,omitempty"`
	Relocations map[string]int `json:"dynamic_relocations"`
	// Versions lists each import's required symbol version, which the
	// generated package binds with dlvsym.
	Versions        []VersionedImport `json:"versioned_imports,omitempty"`
	Exports         []Export          `json:"exports"`
	FunctionSymbols int               `json:"function_symbols"`
	// DroppedFunctionSymbols counts function names left out where Go's
	// function lookup table would overflow; their code is unchanged.
	DroppedFunctionSymbols int    `json:"dropped_function_symbols,omitempty"`
	UnwindSymbol           string `json:"unwind_symbol,omitempty"`
}

// Range is a half-open range of image offsets.
type Range struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// Export is a symbol the shared object exports by default version.
type Export struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}

// VersionedImport is a versioned undefined dynamic symbol.
type VersionedImport struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Library string `json:"library"`
}

const (
	sharedObjectMaxImage = 512 << 20
	// sharedObjectPad follows the image so that the page holding its last
	// writable byte cannot also hold Go code, for pages up to this size.
	sharedObjectPad = 64 << 10
	// Go's findfunctab stores a byte index per 256-byte subbucket of a 4 KiB
	// bucket, so at most 255 functions may start in one 4 KiB of text. Leave
	// room for Go or native code sharing the image's first and last buckets.
	sharedObjectSymbolsPerBucket = 192

	dtRELR    = elf.DynTag(36)
	dtRELRSZ  = elf.DynTag(35)
	dtRELRENT = elf.DynTag(37)
)

// IsSharedObject reports whether b is an ELF shared object or PIE.
func IsSharedObject(b []byte) bool {
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Type == elf.ET_DYN
}

// Dynamic relocation kinds of a shared object, per architecture.
type soKind int

const (
	soUnknown soKind = iota
	soNone
	soRelative   // image base + addend
	soAbsolute   // symbol + addend: ABS64, GLOB_DAT, JUMP_SLOT
	soModule     // TLS module ID for __tls_get_addr; Bao's resolver ignores it
	soTLSOffset  // offset within the module's TLS block
	soDescriptor // TLS descriptor: resolver, then its argument
	soStaticTLS  // initial-exec thread-pointer offset
	soIndirect   // IFUNC
	soCopy       // copy relocation
)

// Marker relocations for TLS slots in a shared-object image. The TLS
// lowering pass replaces them once the template layout is known.
const (
	relocImageTLSOffset     = elf.R_AARCH64(0x7fff0001) // 64-bit template offset of the symbol + addend
	relocImageTLSDescriptor = elf.R_AARCH64(0x7fff0002) // Bao's descriptor thunk, then the template offset
)

type soArch struct {
	abs         elf.R_AARCH64 // the image's link-time 64-bit absolute relocation
	kinds       map[uint32]soKind
	name        func(uint32) string
	descriptors bool // Bao's helper provides a TLS descriptor thunk
	resolver    bool // __tls_get_addr is redirected to Bao's resolver
}

var soArches = map[elf.Machine]soArch{
	elf.EM_AARCH64: {elf.R_AARCH64_ABS64, map[uint32]soKind{
		uint32(elf.R_AARCH64_NONE): soNone, uint32(elf.R_AARCH64_RELATIVE): soRelative, uint32(elf.R_AARCH64_ABS64): soAbsolute,
		uint32(elf.R_AARCH64_GLOB_DAT): soAbsolute, uint32(elf.R_AARCH64_JUMP_SLOT): soAbsolute, uint32(elf.R_AARCH64_TLS_DTPMOD64): soModule,
		uint32(elf.R_AARCH64_TLS_DTPREL64): soTLSOffset, uint32(elf.R_AARCH64_TLS_TPREL64): soStaticTLS, uint32(elf.R_AARCH64_TLSDESC): soDescriptor,
		uint32(elf.R_AARCH64_IRELATIVE): soIndirect, uint32(elf.R_AARCH64_COPY): soCopy,
	}, func(t uint32) string { return elf.R_AARCH64(t).String() }, true, false},
	elf.EM_X86_64: {elf.R_AARCH64(elf.R_X86_64_64), map[uint32]soKind{
		uint32(elf.R_X86_64_NONE): soNone, uint32(elf.R_X86_64_RELATIVE): soRelative, uint32(elf.R_X86_64_64): soAbsolute,
		uint32(elf.R_X86_64_GLOB_DAT): soAbsolute, uint32(elf.R_X86_64_JMP_SLOT): soAbsolute, uint32(elf.R_X86_64_DTPMOD64): soModule,
		uint32(elf.R_X86_64_DTPOFF64): soTLSOffset, uint32(elf.R_X86_64_TPOFF64): soStaticTLS, uint32(elf.R_X86_64_TLSDESC): soDescriptor,
		uint32(elf.R_X86_64_IRELATIVE): soIndirect, uint32(elf.R_X86_64_COPY): soCopy,
	}, func(t uint32) string { return elf.R_X86_64(t).String() }, true, true},
	elf.EM_LOONGARCH: {elf.R_AARCH64(elf.R_LARCH_64), map[uint32]soKind{
		uint32(elf.R_LARCH_NONE): soNone, uint32(elf.R_LARCH_RELATIVE): soRelative, uint32(elf.R_LARCH_64): soAbsolute,
		uint32(elf.R_LARCH_JUMP_SLOT): soAbsolute, uint32(elf.R_LARCH_TLS_DTPMOD64): soModule, uint32(elf.R_LARCH_TLS_DTPREL64): soTLSOffset,
		uint32(elf.R_LARCH_TLS_TPREL64): soStaticTLS, uint32(elf.R_LARCH_TLS_DESC64): soDescriptor, uint32(elf.R_LARCH_IRELATIVE): soIndirect,
		uint32(elf.R_LARCH_COPY): soCopy,
	}, func(t uint32) string { return elf.R_LARCH(t).String() }, false, true},
	elf.EM_PPC64: {elf.R_AARCH64(elf.R_PPC64_ADDR64), map[uint32]soKind{
		uint32(elf.R_PPC64_NONE): soNone, uint32(elf.R_PPC64_RELATIVE): soRelative, uint32(elf.R_PPC64_ADDR64): soAbsolute,
		uint32(elf.R_PPC64_GLOB_DAT): soAbsolute, uint32(elf.R_PPC64_JMP_SLOT): soAbsolute, uint32(elf.R_PPC64_DTPMOD64): soModule,
		uint32(elf.R_PPC64_DTPREL64): soTLSOffset, uint32(elf.R_PPC64_TPREL64): soStaticTLS, uint32(elf.R_PPC64_IRELATIVE): soIndirect,
		uint32(elf.R_PPC64_COPY): soCopy,
	}, func(t uint32) string { return elf.R_PPC64(t).String() }, false, true},
}

type delinked struct {
	m       *image
	info    *SharedObject
	ehFrame int64
}

type dynReloc struct {
	relr bool // packed relative relocation
	off  uint64
	typ  elf.R_AARCH64
	sym  uint32
	add  int64
}

func delink(data []byte, ns string) (*delinked, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_DYN {
		return nil, fmt.Errorf("requires a little-endian ELF64 shared object, not %s/%s/%s", f.Class, f.Data, f.Type)
	}
	arch, ok := soArches[f.Machine]
	if !ok {
		return nil, fmt.Errorf("unsupported shared-object machine %s", f.Machine)
	}
	flags := binary.LittleEndian.Uint32(data[48:])
	if f.Machine == elf.EM_PPC64 && flags&3 != 2 {
		return nil, fmt.Errorf("requires PowerPC64 ELFv2 ABI")
	}
	if f.Machine == elf.EM_LOONGARCH && (flags&7 != 3 || flags&0xc0 != 0x40) {
		return nil, fmt.Errorf("requires LoongArch LP64D object ABI v1")
	}
	var loads []*elf.Prog
	var tls, relro, ehHdr, dynamic *elf.Prog
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			loads = append(loads, p)
		case elf.PT_TLS:
			tls = p
		case elf.PT_GNU_RELRO:
			relro = p
		case elf.PT_GNU_EH_FRAME:
			ehHdr = p
		case elf.PT_DYNAMIC:
			dynamic = p
		case elf.PT_INTERP:
			return nil, fmt.Errorf("input is a position-independent executable, not a shared library")
		}
	}
	if len(loads) == 0 {
		return nil, fmt.Errorf("shared object has no loadable segments")
	}
	// debug/elf reads dynamic tags and symbols through section headers and
	// reports none when they are missing, which would drop relocations.
	if ds := f.SectionByType(elf.SHT_DYNAMIC); dynamic == nil || ds == nil || ds.Addr != dynamic.Vaddr || f.SectionByType(elf.SHT_DYNSYM) == nil {
		return nil, fmt.Errorf("shared object needs PT_DYNAMIC and its section headers (.dynamic, .dynsym)")
	}
	sort.Slice(loads, func(i, j int) bool { return loads[i].Vaddr < loads[j].Vaddr })
	var end uint64
	for i, p := range loads {
		if p.Memsz < p.Filesz || p.Vaddr+p.Memsz < p.Vaddr || p.Vaddr+p.Memsz > sharedObjectMaxImage {
			return nil, fmt.Errorf("loadable segment at %#x exceeds translation bounds", p.Vaddr)
		}
		if i > 0 && p.Vaddr < loads[i-1].Vaddr+loads[i-1].Memsz {
			return nil, fmt.Errorf("overlapping loadable segments at %#x", p.Vaddr)
		}
		if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
			return nil, fmt.Errorf("writable executable segment at %#x is unsupported", p.Vaddr)
		}
		end = max(end, p.Vaddr+p.Memsz)
	}
	img := make([]byte, end)
	for _, p := range loads {
		if _, err := p.ReadAt(img[p.Vaddr:p.Vaddr+p.Filesz], 0); err != nil {
			return nil, fmt.Errorf("read segment at %#x: %w", p.Vaddr, err)
		}
	}
	segment := func(off, n uint64, want elf.ProgFlag) bool {
		for _, p := range loads {
			if off >= p.Vaddr && off+n >= off && off+n <= p.Vaddr+p.Memsz {
				return p.Flags&want == want
			}
		}
		return false
	}
	sum := sha256.Sum256(data)
	info := &SharedObject{SHA256: fmt.Sprintf("%x", sum), BaseSymbol: ns + "so_base", Relocations: map[string]int{}}

	dyn := func(tag elf.DynTag) (uint64, bool, error) {
		v, err := f.DynValue(tag)
		if err != nil {
			return 0, false, err
		}
		if len(v) == 0 {
			return 0, false, nil
		}
		return v[0], true, nil
	}
	if names, err := f.DynString(elf.DT_SONAME); err == nil && len(names) != 0 {
		info.SONAME = names[0]
	} else if err != nil {
		return nil, fmt.Errorf("read dynamic section: %w", err)
	}
	if info.Needed, err = f.DynString(elf.DT_NEEDED); err != nil {
		return nil, err
	}
	for _, tag := range []elf.DynTag{elf.DT_TEXTREL, elf.DT_REL, elf.DT_RELSZ, elf.DT_PREINIT_ARRAY} {
		if _, ok, err := dyn(tag); err != nil {
			return nil, err
		} else if ok {
			return nil, fmt.Errorf("shared object uses %s, which is unsupported", tag)
		}
	}
	if flags, _, err := dyn(elf.DT_FLAGS); err != nil {
		return nil, err
	} else if elf.DynFlag(flags)&elf.DF_TEXTREL != 0 {
		return nil, fmt.Errorf("shared object has text relocations")
	}
	if flags, _, err := dyn(elf.DT_FLAGS_1); err != nil {
		return nil, err
	} else if elf.DynFlag1(flags)&elf.DF_1_PIE != 0 {
		return nil, fmt.Errorf("input is a position-independent executable, not a shared library")
	}
	if kind, ok, err := dyn(elf.DT_PLTREL); err != nil {
		return nil, err
	} else if ok && elf.DynTag(kind) != elf.DT_RELA {
		return nil, fmt.Errorf("PLT relocations must be RELA")
	}

	var relocs []dynReloc
	type table struct{ addr, size uint64 }
	var tables []table
	for _, t := range [][3]elf.DynTag{{elf.DT_RELA, elf.DT_RELASZ, elf.DT_RELAENT}, {elf.DT_JMPREL, elf.DT_PLTRELSZ, 0}} {
		addr, ok, err := dyn(t[0])
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		size, _, err := dyn(t[1])
		if err != nil {
			return nil, err
		}
		if t[2] != 0 {
			if ent, ok, err := dyn(t[2]); err != nil {
				return nil, err
			} else if ok && ent != 24 {
				return nil, fmt.Errorf("unsupported RELA entry size %d", ent)
			}
		}
		if size%24 != 0 || addr+size < addr || addr+size > end || !segment(addr, size, elf.PF_R) {
			return nil, fmt.Errorf("dynamic relocation table outside the loaded image")
		}
		// Some linkers count .rela.plt in DT_RELASZ as well.
		inside := false
		for _, o := range tables {
			if addr >= o.addr && addr+size <= o.addr+o.size {
				inside = true
			}
		}
		if inside {
			continue
		}
		tables = append(tables, table{addr, size})
		for p := img[addr : addr+size]; len(p) > 0; p = p[24:] {
			word := binary.LittleEndian.Uint64(p[8:])
			relocs = append(relocs, dynReloc{off: binary.LittleEndian.Uint64(p), typ: elf.R_AARCH64(uint32(word)), sym: uint32(word >> 32), add: int64(binary.LittleEndian.Uint64(p[16:]))})
		}
	}
	if addr, ok, err := dyn(dtRELR); err != nil {
		return nil, err
	} else if ok {
		size, _, err := dyn(dtRELRSZ)
		if err != nil {
			return nil, err
		}
		if ent, ok, err := dyn(dtRELRENT); err != nil {
			return nil, err
		} else if ok && ent != 8 {
			return nil, fmt.Errorf("unsupported RELR entry size %d", ent)
		}
		if size%8 != 0 || addr+size < addr || addr+size > end {
			return nil, fmt.Errorf("RELR table outside the loaded image")
		}
		// Packed relative relocations keep their addend in place.
		var where uint64
		for p := img[addr : addr+size]; len(p) > 0; p = p[8:] {
			word := binary.LittleEndian.Uint64(p)
			var places []uint64
			if word&1 == 0 {
				places, where = []uint64{word}, word+8
			} else {
				for bit := uint64(1); bit < 64; bit++ {
					if word>>bit&1 != 0 {
						places = append(places, where+(bit-1)*8)
					}
				}
				where += 63 * 8
			}
			for _, off := range places {
				if off+8 < off || off+8 > end {
					return nil, fmt.Errorf("RELR relocation outside the loaded image")
				}
				relocs = append(relocs, dynReloc{off: off, relr: true, add: int64(binary.LittleEndian.Uint64(img[off:]))})
			}
		}
	}

	syms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	blob := section{name: ".bao.shared_object", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4096}
	m := &image{machine: f.Machine, flags: flags, sections: []section{{}, blob}, symbols: []symbol{{}, {info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_SECTION), sect: 1}}}
	const blobSect, blobSym = 1, 1
	var tlsSect uint16
	var tlsSym uint32
	if tls != nil {
		if tls.Memsz < tls.Filesz || tls.Memsz > 1<<30 || !segment(tls.Vaddr, tls.Filesz, 0) {
			return nil, fmt.Errorf("TLS segment outside the loaded image")
		}
		template := make([]byte, tls.Memsz)
		copy(template, img[tls.Vaddr:tls.Vaddr+tls.Filesz])
		tlsSect = m.addSection(section{name: ".tdata", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS, align: max(1, tls.Align), size: tls.Memsz, data: template})
		m.symbols = append(m.symbols, symbol{name: ns + "so_tls", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_TLS), sect: tlsSect})
		tlsSym = uint32(len(m.symbols) - 1)
	}
	imports := map[string]uint32{}
	versions := map[string]VersionedImport{}
	importSym := func(s elf.Symbol) uint32 {
		if i, ok := imports[s.Name]; ok {
			if elf.ST_BIND(s.Info) != elf.STB_WEAK {
				m.symbols[i].info = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE)
			}
			return i
		}
		bind := elf.STB_GLOBAL
		if elf.ST_BIND(s.Info) == elf.STB_WEAK {
			bind = elf.STB_WEAK
		}
		m.symbols = append(m.symbols, symbol{name: s.Name, info: byte(bind)<<4 | byte(elf.STT_NOTYPE)})
		imports[s.Name] = uint32(len(m.symbols) - 1)
		if s.Version != "" {
			versions[s.Name] = VersionedImport{Name: s.Name, Version: s.Version, Library: s.Library}
		}
		return imports[s.Name]
	}
	// Each relocated 8-byte slot, for constructor tables and overlap checks.
	slots := map[uint64]reloc{}
	var out, template []reloc
	for _, r := range relocs {
		kind, name := arch.kinds[uint32(r.typ)], arch.name(uint32(r.typ))
		if r.relr {
			kind, name = soRelative, "RELR"
		}
		width := uint64(8)
		if kind == soDescriptor {
			width = 16
		}
		if kind == soNone {
			continue
		}
		info.Relocations[name]++
		if r.off%8 != 0 || !segment(r.off, width, elf.PF_W) {
			return nil, fmt.Errorf("%s at %#x is not an aligned slot in a writable segment; text relocations are unsupported", name, r.off)
		}
		var sym elf.Symbol
		if r.sym != 0 {
			if int(r.sym) > len(syms) {
				return nil, fmt.Errorf("%s at %#x names an invalid dynamic symbol", name, r.off)
			}
			sym = syms[r.sym-1]
		}
		q := reloc{off: r.off, sym: blobSym, typ: arch.abs, add: r.add}
		switch kind {
		case soRelative:
			if r.sym != 0 {
				return nil, fmt.Errorf("%s at %#x names a symbol", name, r.off)
			}
		case soAbsolute:
			if r.sym == 0 {
				return nil, fmt.Errorf("%s at %#x has no symbol", name, r.off)
			}
			switch {
			case sym.Section == elf.SHN_UNDEF:
				if sym.Name == "__tls_get_addr_opt" {
					return nil, fmt.Errorf("shared object uses __tls_get_addr_opt; link it with --no-tls-get-addr-optimize")
				}
				q.sym = importSym(sym)
			case elf.ST_TYPE(sym.Info) == elf.STT_TLS:
				return nil, fmt.Errorf("%s at %#x takes the address of thread-local %s", name, r.off, sym.Name)
			case elf.ST_TYPE(sym.Info) == elf.STT_GNU_IFUNC:
				return nil, fmt.Errorf("%s at %#x refers to indirect function %s, which is unsupported", name, r.off, sym.Name)
			case sym.Section == elf.SHN_ABS:
				binary.LittleEndian.PutUint64(img[r.off:], sym.Value+uint64(r.add))
				continue
			case sym.Section >= elf.SHN_LORESERVE:
				return nil, fmt.Errorf("%s at %#x refers to unsupported symbol %s", name, r.off, sym.Name)
			default:
				q.add += int64(sym.Value)
			}
		case soModule, soTLSOffset, soDescriptor:
			if kind == soDescriptor && !arch.descriptors || kind != soDescriptor && !arch.resolver {
				return nil, fmt.Errorf("shared object uses %s, which Bao's %s TLS runtime does not provide", name, f.Machine)
			}
			offset := r.add
			if r.sym != 0 {
				if sym.Section == elf.SHN_UNDEF {
					return nil, fmt.Errorf("thread-local %s is imported from another shared object, which is unsupported", sym.Name)
				}
				if elf.ST_TYPE(sym.Info) != elf.STT_TLS {
					return nil, fmt.Errorf("%s at %#x names non-TLS symbol %s", name, r.off, sym.Name)
				}
				offset += int64(sym.Value)
			}
			if kind == soModule {
				// Bao's resolver reads only the offset word.
				clear(img[r.off : r.off+8])
				if _, dup := slots[r.off]; dup {
					return nil, fmt.Errorf("overlapping dynamic relocations at %#x", r.off)
				}
				slots[r.off] = reloc{}
				continue
			}
			if tls == nil || offset < 0 || uint64(offset) >= max(tls.Memsz, 1) {
				return nil, fmt.Errorf("%s at %#x is outside the TLS segment", name, r.off)
			}
			q = reloc{off: r.off, sym: tlsSym, typ: relocImageTLSOffset, add: offset}
			if kind == soDescriptor {
				q.typ = relocImageTLSDescriptor
			}
		case soStaticTLS:
			return nil, fmt.Errorf("shared object uses initial-exec TLS (%s), which needs a fixed thread-pointer offset; build it with the default global-dynamic model", name)
		case soIndirect:
			return nil, fmt.Errorf("shared object uses indirect functions (%s), which are unsupported", name)
		case soCopy:
			return nil, fmt.Errorf("shared object uses copy relocations (%s), which are unsupported", name)
		default:
			return nil, fmt.Errorf("unsupported dynamic relocation %s at %#x", name, r.off)
		}
		for w := uint64(0); w < width; w += 8 {
			if _, dup := slots[r.off+w]; dup {
				return nil, fmt.Errorf("overlapping dynamic relocations at %#x", r.off+w)
			}
			slots[r.off+w] = q
		}
		clear(img[r.off : r.off+width])
		out = append(out, q)
		// TLS initializers are relocated in the per-thread template as well.
		if tls != nil && q.typ == arch.abs && r.off >= tls.Vaddr && r.off < tls.Vaddr+tls.Filesz {
			if r.off+8 > tls.Vaddr+tls.Filesz {
				return nil, fmt.Errorf("relocation at %#x crosses the end of the TLS initializer", r.off)
			}
			t := q
			t.off -= tls.Vaddr
			clear(m.sections[tlsSect].data[t.off : t.off+8])
			template = append(template, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].off < out[j].off })
	if tls != nil {
		m.sections[tlsSect].relocs = template
	}

	// Constructors run in ELF order: DT_INIT, then DT_INIT_ARRAY. Bao runs a
	// finalizer table backwards, so DT_FINI leads the DT_FINI_ARRAY entries.
	code := func(what string, target uint64) error {
		if !segment(target, 4, elf.PF_X) || target%4 != 0 {
			return fmt.Errorf("%s target %#x is not in an executable segment", what, target)
		}
		return nil
	}
	tableEntries := func(addrTag, sizeTag elf.DynTag) ([]uint64, error) {
		addr, ok, err := dyn(addrTag)
		if err != nil || !ok {
			return nil, err
		}
		size, _, err := dyn(sizeTag)
		if err != nil {
			return nil, err
		}
		if size%8 != 0 || addr%8 != 0 || addr+size < addr || !segment(addr, size, elf.PF_R) {
			return nil, fmt.Errorf("%s outside the loaded image", addrTag)
		}
		var targets []uint64
		for off := addr; off < addr+size; off += 8 {
			r, ok := slots[off]
			if !ok || r.sym != blobSym || r.typ != arch.abs {
				return nil, fmt.Errorf("%s entry at %#x is not a relocated pointer into the image", addrTag, off)
			}
			if err := code(addrTag.String(), uint64(r.add)); err != nil {
				return nil, err
			}
			targets = append(targets, uint64(r.add))
		}
		return targets, nil
	}
	var inits, finis []uint64
	if v, ok, err := dyn(elf.DT_INIT); err != nil {
		return nil, err
	} else if ok && v != 0 {
		if err := code("DT_INIT", v); err != nil {
			return nil, err
		}
		inits = append(inits, v)
	}
	if v, ok, err := dyn(elf.DT_FINI); err != nil {
		return nil, err
	} else if ok && v != 0 {
		if err := code("DT_FINI", v); err != nil {
			return nil, err
		}
		finis = append(finis, v)
	}
	array, err := tableEntries(elf.DT_INIT_ARRAY, elf.DT_INIT_ARRAYSZ)
	if err != nil {
		return nil, err
	}
	inits = append(inits, array...)
	if array, err = tableEntries(elf.DT_FINI_ARRAY, elf.DT_FINI_ARRAYSZ); err != nil {
		return nil, err
	}
	finis = append(finis, array...)
	for _, t := range []struct {
		name    string
		typ     elf.SectionType
		targets []uint64
	}{{".init_array", elf.SHT_INIT_ARRAY, inits}, {".fini_array", elf.SHT_FINI_ARRAY, finis}} {
		if len(t.targets) == 0 {
			continue
		}
		s := section{name: t.name, typ: t.typ, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: uint64(len(t.targets) * 8), data: make([]byte, len(t.targets)*8)}
		for i, target := range t.targets {
			s.relocs = append(s.relocs, reloc{off: uint64(i * 8), sym: blobSym, typ: arch.abs, add: int64(target)})
		}
		m.addSection(s)
	}

	// Unwind tables are registered in place: their PC-relative pointers stay
	// valid because the image keeps its layout.
	d := &delinked{m: m, info: info, ehFrame: -1}
	if ehHdr != nil {
		h := ehHdr.Vaddr
		if h+8 < h || h+8 > end || img[h] != 1 {
			return nil, fmt.Errorf("unsupported .eh_frame_hdr")
		}
		if img[h+1] != 0x1b { // DW_EH_PE_pcrel | DW_EH_PE_sdata4
			return nil, fmt.Errorf("unsupported .eh_frame_hdr pointer encoding %#x", img[h+1])
		}
		frame := int64(h+4) + int64(int32(binary.LittleEndian.Uint32(img[h+4:])))
		if frame < 0 || uint64(frame) >= end || segment(uint64(frame), 4, elf.PF_W) || !segment(uint64(frame), 4, elf.PF_R) {
			return nil, fmt.Errorf(".eh_frame outside read-only image data")
		}
		terminated := false
		for off := uint64(frame); off+4 <= end && segment(off, 4, elf.PF_R); {
			n := uint64(binary.LittleEndian.Uint32(img[off:]))
			if n == 0 {
				terminated = true
				break
			}
			if n == 0xffffffff {
				return nil, fmt.Errorf("64-bit .eh_frame records are unsupported")
			}
			off += 4 + n
		}
		if !terminated {
			return nil, fmt.Errorf(".eh_frame has no terminator, so it cannot be registered")
		}
		d.ehFrame = frame
		info.UnwindSymbol = ns + "unwind_so"
	}

	// Pages made writable at run time must not hold executable code: neither
	// the image's own nor Go's code around the image.
	page := uint64(sharedObjectPad)
	var writable []Range
	for _, p := range loads {
		if p.Flags&elf.PF_W == 0 {
			continue
		}
		r := Range{p.Vaddr, p.Vaddr + p.Memsz}
		writable = append(writable, r)
		below, above := r.Start, end+sharedObjectPad-r.End
		for _, q := range loads {
			if q.Flags&elf.PF_X == 0 {
				continue
			}
			if q.Vaddr+q.Memsz <= r.Start {
				below = min(below, r.Start-(q.Vaddr+q.Memsz))
			} else if q.Vaddr >= r.End {
				above = min(above, q.Vaddr-r.End)
			}
		}
		for page > 4096 && (below < page || above < page) {
			page /= 2
		}
		if below < page || above < page {
			return nil, fmt.Errorf("writable segment at %#x is within 4 KiB of executable code", p.Vaddr)
		}
	}
	info.MaxPageSize = page
	info.Writable = writable
	m.sections[blobSect].writable = writable
	if relro != nil {
		if !segment(relro.Vaddr, relro.Memsz, elf.PF_W) {
			return nil, fmt.Errorf("PT_GNU_RELRO is not inside one writable segment")
		}
		info.RELRO = []Range{{relro.Vaddr, relro.Vaddr + relro.Memsz}}
	}

	// Exports keep their default-version names. The image keeps its own
	// references to them: a shared object linked into one executable has
	// nothing to interpose.
	exported := map[uint64]bool{}
	names := map[string]bool{}
	for _, s := range syms {
		bind, typ := elf.ST_BIND(s.Info), elf.ST_TYPE(s.Info)
		if s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE || (bind != elf.STB_GLOBAL && bind != elf.STB_WEAK) || s.Name == "" {
			continue
		}
		if s.HasVersion && s.VersionIndex.IsHidden() {
			continue
		}
		kind := map[elf.SymType]string{elf.STT_FUNC: "func", elf.STT_OBJECT: "object", elf.STT_NOTYPE: "notype"}[typ]
		switch {
		case typ == elf.STT_TLS:
			continue
		case typ == elf.STT_GNU_IFUNC:
			return nil, fmt.Errorf("exported indirect function %s is unsupported", s.Name)
		case kind == "":
			continue
		}
		if s.Value+s.Size < s.Value || s.Value+s.Size > end {
			return nil, fmt.Errorf("exported %s lies outside the loaded image", s.Name)
		}
		if names[s.Name] {
			return nil, fmt.Errorf("shared object exports %s twice", s.Name)
		}
		names[s.Name] = true
		m.symbols = append(m.symbols, symbol{name: s.Name, info: byte(bind)<<4 | byte(typ), sect: blobSect, value: s.Value, size: s.Size})
		info.Exports = append(info.Exports, Export{Name: s.Name, Kind: kind, Offset: s.Value, Size: s.Size})
		exported[s.Value] = true
	}
	sort.Slice(info.Exports, func(i, j int) bool { return info.Exports[i].Name < info.Exports[j].Name })
	if _, ok := names[info.BaseSymbol]; ok {
		return nil, fmt.Errorf("shared object exports reserved name %s", info.BaseSymbol)
	}
	m.symbols = append(m.symbols, symbol{name: info.BaseSymbol, info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE), sect: blobSect})

	// Name the remaining functions so Go tracebacks and profiles can tell
	// them apart. Go's function lookup table bounds how many may start in
	// one 4 KiB bucket; exports always stay, local names give way.
	perBucket := map[uint64]int{}
	for _, s := range m.symbols {
		if s.sect == blobSect && s.name != "" {
			perBucket[s.value/4096]++
		}
	}
	for b, n := range perBucket {
		if n > sharedObjectSymbolsPerBucket {
			return nil, fmt.Errorf("shared object exports %d symbols within 4 KiB at %#x; Go's function table allows %d", n, b*4096, sharedObjectSymbolsPerBucket)
		}
	}
	if locals, err := f.Symbols(); err == nil {
		sort.SliceStable(locals, func(i, j int) bool { return locals[i].Value < locals[j].Value })
		for _, s := range locals {
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE || s.Name == "" || s.Name[0] == '$' || exported[s.Value] || !segment(s.Value, max(s.Size, 1), elf.PF_X) {
				continue
			}
			exported[s.Value] = true
			if perBucket[s.Value/4096] >= sharedObjectSymbolsPerBucket {
				info.DroppedFunctionSymbols++
				continue
			}
			perBucket[s.Value/4096]++
			m.symbols = append(m.symbols, symbol{name: s.Name, info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FUNC), sect: blobSect, value: s.Value, size: s.Size})
			info.FunctionSymbols++
		}
	} else if !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}

	for _, v := range versions {
		info.Versions = append(info.Versions, v)
	}
	sort.Slice(info.Versions, func(i, j int) bool { return info.Versions[i].Name < info.Versions[j].Name })
	info.ImageSize = end + sharedObjectPad
	info.CheckOffset = (end + 7) &^ 7
	out = append(out, reloc{off: info.CheckOffset, sym: blobSym, typ: arch.abs})
	b := &m.sections[blobSect]
	b.data = append(img, make([]byte, sharedObjectPad)...)
	b.size = uint64(len(b.data))
	b.relocs = out
	return d, nil
}

// lowerImageTLS fills a shared-object image's TLS slots once the template
// layout is known: offset words for Bao's __tls_get_addr resolver, and
// descriptors whose first word calls Bao's thunk. It counts both.
func lowerImageTLS(m *image, offsets map[uint16]uint64, size uint64, thunk func() uint32) (int, error) {
	descriptors := 0
	for si := range m.sections {
		s := &m.sections[si]
		if s.writable == nil {
			continue
		}
		out := s.relocs[:0]
		for _, r := range s.relocs {
			if r.typ != relocImageTLSOffset && r.typ != relocImageTLSDescriptor {
				out = append(out, r)
				continue
			}
			sym := m.symbols[r.sym]
			base, ok := offsets[sym.sect]
			word := r.off
			if r.typ == relocImageTLSDescriptor {
				word += 8
			}
			if !ok || r.add < 0 || base+sym.value+uint64(r.add) >= size || word+8 > uint64(len(s.data)) {
				return 0, fmt.Errorf("shared-object TLS slot at %#x is outside the TLS template", r.off)
			}
			binary.LittleEndian.PutUint64(s.data[word:], base+sym.value+uint64(r.add))
			if r.typ == relocImageTLSDescriptor {
				out = append(out, reloc{off: r.off, sym: thunk(), typ: soArches[m.effectiveMachine()].abs})
			}
			descriptors++
		}
		s.relocs = out
	}
	return descriptors, nil
}

// merge appends a relocatable image's sections and symbols to m.
func (m *image) merge(o *image) error {
	if o.effectiveMachine() != m.effectiveMachine() {
		return fmt.Errorf("cannot combine %s and %s objects", m.arch(), o.arch())
	}
	if len(m.sections)+len(o.sections) >= int(elf.SHN_LORESERVE)-3 {
		return fmt.Errorf("too many sections")
	}
	defined := map[string]bool{}
	for _, s := range m.symbols {
		if s.sect != 0 && elf.ST_BIND(s.info) == elf.STB_GLOBAL {
			defined[s.name] = true
		}
	}
	for _, s := range o.symbols {
		if s.sect != 0 && elf.ST_BIND(s.info) == elf.STB_GLOBAL && defined[s.name] {
			return fmt.Errorf("%s is defined by both the shared object and the relocatable input", s.name)
		}
	}
	sections, symbols := uint16(len(m.sections)-1), uint32(len(m.symbols)-1)
	for _, s := range o.sections[1:] {
		relocs := make([]reloc, len(s.relocs))
		for i, r := range s.relocs {
			if r.sym != 0 {
				r.sym += symbols
			}
			relocs[i] = r
		}
		s.relocs = relocs
		if s.typ == elf.SHT_RELA || s.typ == elf.SHT_REL {
			s.info += uint32(sections)
		}
		m.sections = append(m.sections, s)
	}
	for _, s := range o.symbols[1:] {
		if s.sect != 0 && s.sect < uint16(elf.SHN_LORESERVE) {
			s.sect += sections
		}
		m.symbols = append(m.symbols, s)
	}
	return nil
}

// checkImageCalls rejects direct PowerPC64 calls from relocatable code into
// a shared-object image. The image's functions derive their own TOC from r12
// at the global entry point, which a direct branch does not set; Go's linker
// has no cross-TOC call stubs. Calls through function pointers work.
func checkImageCalls(m *image) error {
	if m.effectiveMachine() != elf.EM_PPC64 {
		return nil
	}
	inImage := map[string]bool{}
	for _, q := range m.symbols {
		if q.sect != 0 && q.sect < uint16(elf.SHN_LORESERVE) && m.sections[q.sect].writable != nil && elf.ST_BIND(q.info) != elf.STB_LOCAL {
			inImage[q.name] = true
		}
	}
	for _, s := range m.sections {
		if s.writable != nil {
			continue
		}
		for _, r := range s.relocs {
			t := elf.R_PPC64(r.typ)
			target := m.symbols[r.sym]
			if (t == elf.R_PPC64_REL24 || t == elf.R_PPC64_REL24_NOTOC || t == elf.R_PPC64_REL14) && (target.sect != 0 && target.sect < uint16(elf.SHN_LORESERVE) && m.sections[target.sect].writable != nil || target.sect == 0 && inImage[target.name]) {
				return fmt.Errorf("on ppc64le, %s calls shared-object function %s directly; call it through a function pointer", s.name, m.symbols[r.sym].name)
			}
		}
	}
	return nil
}

// checkVersions requires each versioned import to exist in its sysroot
// provider. glibc keeps old versions beside new defaults, sometimes as other
// code (libm's GLIBC_2.29 exp, log and pow drop SVID error handling), so the
// generated package binds the required version with dlvsym.
func checkVersions(root string, imports []Import, versions []VersionedImport) error {
	provider := map[string]string{}
	for _, b := range imports {
		provider[b.Remote] = b.Library
	}
	cache := map[string]map[string]bool{}
	var missing []string
	for _, v := range versions {
		lib := provider[v.Name]
		if lib == "" {
			continue
		}
		have, ok := cache[lib]
		if !ok {
			path := sysrootLibrary(root, lib)
			if path == "" {
				return fmt.Errorf("missing target library %s", lib)
			}
			f, err := elf.Open(path)
			if err != nil {
				return err
			}
			syms, err := f.DynamicSymbols()
			f.Close()
			if err != nil {
				return err
			}
			have = map[string]bool{}
			for _, s := range syms {
				if s.Section != elf.SHN_UNDEF {
					have[s.Name+"@"+s.Version] = true
				}
			}
			cache[lib] = have
		}
		if !have[v.Name+"@"+v.Version] {
			missing = append(missing, fmt.Sprintf("%s@%s (in %s)", v.Name, v.Version, lib))
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("target sysroot lacks symbol versions the shared object requires: %s", strings.Join(missing, ", "))
	}
	return nil
}

func sysrootLibrary(root, name string) string {
	for _, dir := range sysrootLibraryDirs {
		candidate := filepath.Join(root, dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
