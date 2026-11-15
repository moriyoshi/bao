package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var le = binary.LittleEndian

const (
	sectionHeaderSize = 64
	symbolSize        = 24
	// LLVM section types that refer to symbol table indices.
	shtCREL        elf.SectionType = 0x40000014
	shtLLVMAddrsig elf.SectionType = 0x6fff4c03
	shtLLVMCGProf  elf.SectionType = 0x6fff4c09
)

type elfSection struct {
	name                  string
	nameOffset            uint32
	typ                   elf.SectionType
	flags                 elf.SectionFlag
	offset, size, entsize uint64
	link, info            uint32
}

type elfSymbol struct {
	name  string
	info  byte
	other byte
	shndx uint16
	value uint64
}

func (s elfSymbol) global() bool { return elf.ST_BIND(s.info) != elf.STB_LOCAL }

func (s elfSymbol) defined() bool { return elf.SectionIndex(s.shndx) != elf.SHN_UNDEF }

func (s elfSymbol) common() bool { return elf.SectionIndex(s.shndx) == elf.SHN_COMMON }

// mapping reports an ARM, AArch64 or RISC-V mapping symbol such as $x or
// $d.42, which marks code and data within a section rather than naming it.
func (s elfSymbol) mapping() bool {
	if len(s.name) < 2 || s.name[0] != '$' || !strings.ContainsRune("xdat", rune(s.name[1])) {
		return false
	}
	return len(s.name) == 2 || s.name[2] == '.'
}

// named excludes section and file symbols, whose names are not symbol names.
func (s elfSymbol) named() bool {
	t := elf.ST_TYPE(s.info)
	return s.name != "" && t != elf.STT_SECTION && t != elf.STT_FILE
}

type elfFile struct {
	data     []byte
	shoff    uint64
	sections []elfSection
	symtab   int // section index, or 0 when the object has no symbol table
	shstrndx int
	symbols  []elfSymbol
}

func parseELF(data []byte) (*elfFile, error) {
	if len(data) < 64 || !bytes.HasPrefix(data, []byte(elf.ELFMAG)) {
		return nil, errors.New("not an ELF object")
	}
	if elf.Class(data[elf.EI_CLASS]) != elf.ELFCLASS64 || elf.Data(data[elf.EI_DATA]) != elf.ELFDATA2LSB {
		return nil, errors.New("only little-endian ELF64 objects are supported")
	}
	if elf.Type(le.Uint16(data[16:])) != elf.ET_REL {
		return nil, errors.New("not an ELF relocatable object")
	}
	f := &elfFile{data: data, shoff: le.Uint64(data[0x28:])}
	if le.Uint16(data[0x3a:]) != sectionHeaderSize {
		return nil, errors.New("unexpected ELF section header size")
	}
	count := uint64(le.Uint16(data[0x3c:]))
	if f.shoff == 0 {
		return f, nil
	}
	if f.shoff > uint64(len(data)) || uint64(len(data))-f.shoff < sectionHeaderSize {
		return nil, errors.New("ELF section headers are out of range")
	}
	if count == 0 {
		// An extended section count is stored in the null section's size.
		count = le.Uint64(data[f.shoff+32:])
	}
	if count > (uint64(len(data))-f.shoff)/sectionHeaderSize {
		return nil, errors.New("ELF section headers are out of range")
	}
	f.sections = make([]elfSection, count)
	for i := range f.sections {
		h := data[f.shoff+uint64(i)*sectionHeaderSize:]
		s := elfSection{
			nameOffset: le.Uint32(h), typ: elf.SectionType(le.Uint32(h[4:])), flags: elf.SectionFlag(le.Uint64(h[8:])),
			offset: le.Uint64(h[24:]), size: le.Uint64(h[32:]), entsize: le.Uint64(h[56:]),
			link: le.Uint32(h[40:]), info: le.Uint32(h[44:]),
		}
		if i > 0 && s.typ != elf.SHT_NOBITS && (s.offset > uint64(len(data)) || s.size > uint64(len(data))-s.offset) {
			return nil, fmt.Errorf("ELF section %d is out of range", i)
		}
		if s.typ == elf.SHT_SYMTAB {
			if f.symtab != 0 {
				return nil, errors.New("ELF object has more than one symbol table")
			}
			f.symtab = i
		}
		f.sections[i] = s
	}
	f.shstrndx = int(le.Uint16(data[0x3e:]))
	if f.shstrndx == int(elf.SHN_XINDEX) {
		f.shstrndx = int(f.sections[0].link)
	}
	if f.shstrndx != 0 {
		if f.shstrndx >= len(f.sections) || f.sections[f.shstrndx].typ != elf.SHT_STRTAB {
			return nil, errors.New("malformed ELF section name table")
		}
		names := f.section(f.shstrndx)
		for i := range f.sections {
			off := f.sections[i].nameOffset
			if int(off) >= len(names) {
				return nil, fmt.Errorf("ELF section %d name is out of range", i)
			}
			if end := bytes.IndexByte(names[off:], 0); end >= 0 {
				f.sections[i].name = string(names[off : int(off)+end])
			}
		}
	}
	if f.symtab == 0 {
		return f, nil
	}
	symtab := f.sections[f.symtab]
	if symtab.size%symbolSize != 0 || int(symtab.link) >= len(f.sections) || f.sections[symtab.link].typ != elf.SHT_STRTAB {
		return nil, errors.New("malformed ELF symbol table")
	}
	strtab := f.section(int(symtab.link))
	f.symbols = make([]elfSymbol, symtab.size/symbolSize)
	for i := range f.symbols {
		e := data[symtab.offset+uint64(i)*symbolSize:]
		name := le.Uint32(e)
		if uint64(name) >= uint64(len(strtab)) && name != 0 {
			return nil, fmt.Errorf("ELF symbol %d name is out of range", i)
		}
		end := bytes.IndexByte(strtab[min(int(name), len(strtab)):], 0)
		if end < 0 {
			return nil, fmt.Errorf("ELF symbol %d name is unterminated", i)
		}
		f.symbols[i] = elfSymbol{name: string(strtab[name : int(name)+end]), info: e[4], other: e[5], shndx: le.Uint16(e[6:])}
	}
	return f, nil
}

func (f *elfFile) section(i int) []byte {
	s := f.sections[i]
	return f.data[s.offset : s.offset+s.size]
}

func (f *elfFile) undefined() []string {
	var out []string
	for _, s := range f.symbols {
		if s.global() && !s.defined() && s.named() {
			out = append(out, s.name)
		}
	}
	return out
}

// indexNames lists definitions, including common symbols, as GNU ar does.
func (f *elfFile) indexNames() []string { return f.defined() }

func (f *elfFile) defined() []string {
	var out []string
	for _, s := range f.symbols {
		if s.global() && s.defined() && s.named() {
			out = append(out, s.name)
		}
	}
	return out
}

// xindex returns the extended section index table of the symbol table, or nil.
func (f *elfFile) xindex() []byte {
	for i, s := range f.sections {
		if s.typ == elf.SHT_SYMTAB_SHNDX && int(s.link) == f.symtab {
			return f.section(i)
		}
	}
	return nil
}

// symbolSection returns the section index symbol i is defined in, or -1 for
// an undefined, absolute or common symbol.
func (f *elfFile) symbolSection(i int, xindex []byte) int {
	switch shndx := f.symbols[i].shndx; {
	case shndx == uint16(elf.SHN_XINDEX) && 4*i+4 <= len(xindex):
		return int(le.Uint32(xindex[4*i:]))
	case shndx != 0 && shndx < uint16(elf.SHN_LORESERVE):
		return int(shndx)
	}
	return -1
}

// droppedSections applies -remove-section and -only-section. Relocation
// sections follow their targets and a section group goes with its last
// member. It returns nil when no section goes, and otherwise each section's
// new index, or -1 for a removed one.
func (f *elfFile) droppedSections(e Edits) ([]int, error) {
	if e.RemoveSection.empty() && e.OnlySection.empty() {
		return nil, nil
	}
	strtab := -1
	if f.symtab != 0 {
		strtab = int(f.sections[f.symtab].link)
	}
	essential := func(i int) bool {
		s := f.sections[i]
		return i == 0 || i == f.symtab || i == strtab || i == f.shstrndx || s.typ == elf.SHT_SYMTAB_SHNDX
	}
	follows := func(s elfSection) bool {
		return s.typ == elf.SHT_REL || s.typ == elf.SHT_RELA || s.typ == shtCREL || s.typ == elf.SHT_GROUP
	}
	drop := make([]bool, len(f.sections))
	for i, s := range f.sections {
		if i == 0 {
			continue
		}
		if e.RemoveSection.Match(s.name) {
			if essential(i) {
				return nil, fmt.Errorf("cannot remove ELF section %s, which the symbol table needs", s.name)
			}
			drop[i] = true
		}
		if !e.OnlySection.empty() && !essential(i) && !follows(s) && !e.OnlySection.Match(s.name) {
			drop[i] = true
		}
	}
	for i, s := range f.sections {
		if (s.typ == elf.SHT_REL || s.typ == elf.SHT_RELA || s.typ == shtCREL) && int(s.info) < len(drop) && drop[s.info] {
			drop[i] = true
		}
	}
	for i, s := range f.sections {
		if s.typ != elf.SHT_GROUP || drop[i] {
			continue
		}
		members := f.section(i)
		kept := false
		for off := 4; off+4 <= len(members); off += 4 {
			if m := int(le.Uint32(members[off:])); m < len(drop) && !drop[m] {
				kept = true
			}
		}
		drop[i] = !kept
	}
	index := make([]int, len(f.sections))
	next, any := 0, false
	for i := range f.sections {
		index[i] = -1
		if !drop[i] {
			index[i] = next
			next++
		}
		any = any || drop[i]
	}
	if !any {
		return nil, nil
	}
	// A kept section may refer to a removed one only as a relocation target,
	// which removes the relocations with it.
	for i, s := range f.sections {
		if drop[i] || i == 0 {
			continue
		}
		if s.link != 0 && int(s.link) < len(drop) && drop[s.link] {
			return nil, fmt.Errorf("cannot remove ELF section %s, which section %s links to", f.sections[s.link].name, s.name)
		}
	}
	return index, nil
}
