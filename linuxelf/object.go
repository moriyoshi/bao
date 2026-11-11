// Package linuxelf translates supported Linux ELF relocatable inputs for Go's
// internal linker. The native ABI and output executable remain Linux ELF.
package linuxelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

type section struct {
	name                 string
	typ                  elf.SectionType
	flags                elf.SectionFlag
	align, entsize, size uint64
	link, info           uint32
	data                 []byte
	relocs               []reloc
}
type symbol struct {
	name        string
	info, other byte
	sect        uint16
	value, size uint64
}
type reloc struct {
	off uint64
	sym uint32
	typ elf.R_AARCH64
	add int64
}
type image struct {
	sections []section
	symbols  []symbol
	anchors  map[uint16]string
	machine  elf.Machine
	flags    uint32
}

func parse(data []byte) (*image, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || (f.Machine != elf.EM_AARCH64 && f.Machine != elf.EM_LOONGARCH && f.Machine != elf.EM_PPC64 && f.Machine != elf.EM_X86_64) || f.Type != elf.ET_REL {
		return nil, fmt.Errorf("requires little-endian Linux AArch64 ELF64 ET_REL, not %s/%s/%s", f.Class, f.Machine, f.Type)
	}
	if len(f.Progs) != 0 || len(f.Sections) >= int(elf.SHN_LORESERVE) {
		return nil, fmt.Errorf("unsupported ELF program headers or extended section indices")
	}
	m := &image{machine: f.Machine, flags: binary.LittleEndian.Uint32(data[48:])}
	if f.Machine == elf.EM_PPC64 && m.flags&3 != 2 {
		return nil, fmt.Errorf("requires PowerPC64 ELFv2 ABI")
	}
	if f.Machine == elf.EM_LOONGARCH {
		// ELF64 plus ABI modifier 3 selects LP64D. Object ABI v1 has the
		// instruction relocations handled here; v0 uses a different model.
		// https://loongson.github.io/LoongArch-Documentation/LoongArch-ELF-ABI-EN.html
		if m.flags&7 != 3 {
			return nil, fmt.Errorf("requires LoongArch LP64D double-float ABI")
		}
		if m.flags&0xc0 != 0x40 {
			return nil, fmt.Errorf("requires LoongArch object ABI v1")
		}
	}
	var symtab *elf.Section
	for _, s := range f.Sections {
		if s.Addralign > 1<<20 || s.Size > 512<<20 {
			return nil, fmt.Errorf("section exceeds translation bounds")
		}
		if s.Addralign != 0 && s.Addralign&(s.Addralign-1) != 0 {
			return nil, fmt.Errorf("section alignment is not a power of two")
		}
		var b []byte
		if s.Type != elf.SHT_NOBITS && s.Type != elf.SHT_NULL {
			b, err = s.Data()
			if err != nil {
				return nil, err
			}
		}
		m.sections = append(m.sections, section{name: s.Name, typ: s.Type, flags: s.Flags, align: max(1, s.Addralign), entsize: s.Entsize, size: s.Size, link: s.Link, info: s.Info, data: bytes.Clone(b)})
		if s.Type == elf.SHT_SYMTAB {
			if symtab != nil {
				return nil, fmt.Errorf("multiple ELF symbol tables")
			}
			symtab = s
		}
	}
	if symtab == nil || symtab.Entsize != 24 || symtab.Size%24 != 0 || int(symtab.Link) >= len(f.Sections) {
		return nil, fmt.Errorf("invalid ELF symbol table")
	}
	strings, err := f.Sections[symtab.Link].Data()
	if err != nil {
		return nil, err
	}
	getstr := func(off uint32) (string, error) {
		if int(off) >= len(strings) {
			return "", fmt.Errorf("ELF string outside table")
		}
		end := bytes.IndexByte(strings[off:], 0)
		if end < 0 {
			return "", fmt.Errorf("unterminated ELF string")
		}
		return string(strings[int(off) : int(off)+end]), nil
	}
	data, err = symtab.Data()
	if err != nil {
		return nil, err
	}
	for len(data) > 0 {
		name, err := getstr(binary.LittleEndian.Uint32(data))
		if err != nil {
			return nil, err
		}
		m.symbols = append(m.symbols, symbol{name: name, info: data[4], other: data[5], sect: binary.LittleEndian.Uint16(data[6:]), value: binary.LittleEndian.Uint64(data[8:]), size: binary.LittleEndian.Uint64(data[16:])})
		data = data[24:]
	}
	for i, s := range m.sections {
		if s.typ != elf.SHT_RELA && s.typ != elf.SHT_REL {
			continue
		}
		if int(s.info) >= len(m.sections) || int(s.link) >= len(m.sections) || m.sections[s.link].typ != elf.SHT_SYMTAB {
			return nil, fmt.Errorf("invalid relocation section")
		}
		if m.sections[s.info].flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if s.typ != elf.SHT_RELA || s.entsize != 24 || len(s.data)%24 != 0 {
			return nil, fmt.Errorf("allocated sections require ELF64 RELA")
		}
		for p := s.data; len(p) > 0; p = p[24:] {
			r := reloc{off: binary.LittleEndian.Uint64(p), sym: uint32(binary.LittleEndian.Uint64(p[8:]) >> 32), typ: elf.R_AARCH64(binary.LittleEndian.Uint32(p[8:])), add: int64(binary.LittleEndian.Uint64(p[16:]))}
			if int(r.sym) >= len(m.symbols) || r.off >= m.sections[s.info].size {
				return nil, fmt.Errorf("relocation outside symbol/section bounds")
			}
			m.sections[s.info].relocs = append(m.sections[s.info].relocs, r)
		}
		// Rebuilt after transformation.
		m.sections[i].data = nil
	}
	return m, nil
}

func (m *image) addSection(s section) uint16 {
	m.sections = append(m.sections, s)
	return uint16(len(m.sections) - 1)
}
func (m *image) addSymbol(name string, sect uint16, value, size uint64) uint32 {
	m.symbols = append(m.symbols, symbol{name: name, info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT), sect: sect, value: value, size: size})
	return uint32(len(m.symbols) - 1)
}

// LLVM section types that carry linker directives.
const (
	shtLLVMLinkerOptions      elf.SectionType = 0x6fff4c01
	shtLLVMDependentLibraries elf.SectionType = 0x6fff4c04
)

func (m *image) encode() ([]byte, error) {
	if len(m.sections) >= int(elf.SHN_LORESERVE)-3 {
		return nil, fmt.Errorf("too many sections")
	}
	// Preserve section indices; replace old metadata with empty nonallocated
	// payloads. ELF link/info fields for live relocations are rebuilt below.
	sections := append([]section(nil), m.sections...)
	for i := range sections {
		if sections[i].typ == elf.SHT_RELA || sections[i].typ == elf.SHT_REL || sections[i].typ == elf.SHT_SYMTAB || sections[i].typ == elf.SHT_STRTAB || sections[i].typ == elf.SHT_GROUP {
			sections[i] = section{name: fmt.Sprintf(".bao.discard.%d", i), typ: elf.SHT_PROGBITS, align: 1}
		}
		// Clang emits empty .linker-options sections (for example with
		// -std=c++20). Go's linker never applied these directives, and cmd/go
		// 1.26.11 rejects .syso files containing either section type.
		if sections[i].typ == shtLLVMLinkerOptions || sections[i].typ == shtLLVMDependentLibraries {
			if sections[i].size != 0 {
				return nil, fmt.Errorf("embedded linker options section %s is unsupported; pass required libraries explicitly", sections[i].name)
			}
			sections[i] = section{name: fmt.Sprintf(".bao.discard.%d", i), typ: elf.SHT_PROGBITS, align: 1}
		}
	}
	var order []int
	for _, local := range []bool{true, false} {
		for i := 1; i < len(m.symbols); i++ {
			if (elf.ST_BIND(m.symbols[i].info) == elf.STB_LOCAL) == local {
				order = append(order, i)
			}
		}
	}
	indices := make([]uint32, len(m.symbols))
	strtab := []byte{0}
	symtab := make([]byte, 24)
	firstGlobal := uint32(1)
	for _, i := range order {
		s := m.symbols[i]
		indices[i] = uint32(len(symtab) / 24)
		off := uint32(len(strtab))
		strtab = append(append(strtab, s.name...), 0)
		b := make([]byte, 24)
		binary.LittleEndian.PutUint32(b, off)
		b[4] = s.info
		b[5] = s.other
		binary.LittleEndian.PutUint16(b[6:], s.sect)
		binary.LittleEndian.PutUint64(b[8:], s.value)
		binary.LittleEndian.PutUint64(b[16:], s.size)
		symtab = append(symtab, b...)
		if elf.ST_BIND(s.info) == elf.STB_LOCAL {
			firstGlobal++
		}
	}
	si := uint32(len(sections))
	sections = append(sections, section{name: ".symtab", typ: elf.SHT_SYMTAB, align: 8, entsize: 24, link: si + 1, info: firstGlobal, data: symtab}, section{name: ".strtab", typ: elf.SHT_STRTAB, align: 1, data: strtab})
	for i, s := range m.sections {
		if len(s.relocs) == 0 || s.flags&elf.SHF_ALLOC == 0 {
			continue
		}
		var b bytes.Buffer
		for _, r := range s.relocs {
			_ = binary.Write(&b, binary.LittleEndian, [3]uint64{r.off, uint64(indices[r.sym])<<32 | uint64(r.typ), uint64(r.add)})
		}
		sections = append(sections, section{name: fmt.Sprintf(".rela.bao.%d", i), typ: elf.SHT_RELA, align: 8, entsize: 24, link: si, info: uint32(i), data: b.Bytes()})
	}
	names := []byte{0}
	nameoffs := make([]uint32, len(sections)+1)
	sections = append(sections, section{name: ".shstrtab", typ: elf.SHT_STRTAB, align: 1})
	for i, s := range sections {
		nameoffs[i] = uint32(len(names))
		names = append(append(names, s.name...), 0)
	}
	sections[len(sections)-1].data = names
	out := make([]byte, 64)
	copy(out, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(out[16:], uint16(elf.ET_REL))
	binary.LittleEndian.PutUint16(out[18:], uint16(m.effectiveMachine()))
	binary.LittleEndian.PutUint32(out[48:], m.flags)
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint16(out[52:], 64)
	binary.LittleEndian.PutUint16(out[58:], 64)
	binary.LittleEndian.PutUint16(out[60:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(out[62:], uint16(len(sections)-1))
	offsets := make([]uint64, len(sections))
	for i := 1; i < len(sections); i++ {
		s := &sections[i]
		align := max(1, s.align)
		if align&(align-1) != 0 {
			return nil, fmt.Errorf("non-power-of-two section alignment")
		}
		for uint64(len(out))%align != 0 {
			out = append(out, 0)
		}
		offsets[i] = uint64(len(out))
		if s.typ != elf.SHT_NOBITS {
			s.size = uint64(len(s.data))
			out = append(out, s.data...)
		}
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	binary.LittleEndian.PutUint64(out[40:], uint64(len(out)))
	for i, s := range sections {
		b := make([]byte, 64)
		if i > 0 {
			binary.LittleEndian.PutUint32(b, nameoffs[i])
			binary.LittleEndian.PutUint32(b[4:], uint32(s.typ))
			binary.LittleEndian.PutUint64(b[8:], uint64(s.flags))
			binary.LittleEndian.PutUint64(b[24:], offsets[i])
			binary.LittleEndian.PutUint64(b[32:], s.size)
			binary.LittleEndian.PutUint32(b[40:], s.link)
			binary.LittleEndian.PutUint32(b[44:], s.info)
			binary.LittleEndian.PutUint64(b[48:], max(1, s.align))
			binary.LittleEndian.PutUint64(b[56:], s.entsize)
		}
		out = append(out, b...)
	}
	return out, nil
}

func (m *image) effectiveMachine() elf.Machine {
	if m.machine == 0 {
		return elf.EM_AARCH64
	}
	return m.machine
}
func (m *image) arch() string {
	switch m.effectiveMachine() {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_LOONGARCH:
		return "loong64"
	case elf.EM_PPC64:
		return "ppc64le"
	}
	return "arm64"
}
