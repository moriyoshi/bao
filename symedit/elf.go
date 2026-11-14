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
	// shtCREL is LLVM's compressed relocation section type.
	shtCREL elf.SectionType = 0x40000014
)

type elfSection struct {
	typ          elf.SectionType
	flags        elf.SectionFlag
	offset, size uint64
	link, info   uint32
}

type elfSymbol struct {
	name  string
	info  byte
	shndx uint16
}

func (s elfSymbol) global() bool { return elf.ST_BIND(s.info) != elf.STB_LOCAL }

func (s elfSymbol) defined() bool { return elf.SectionIndex(s.shndx) != elf.SHN_UNDEF }

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
			typ: elf.SectionType(le.Uint32(h[4:])), flags: elf.SectionFlag(le.Uint64(h[8:])),
			offset: le.Uint64(h[24:]), size: le.Uint64(h[32:]),
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
		f.symbols[i] = elfSymbol{name: string(strtab[name : int(name)+end]), info: e[4], shndx: le.Uint16(e[6:])}
	}
	return f, nil
}

func (f *elfFile) section(i int) []byte {
	s := f.sections[i]
	return f.data[s.offset : s.offset+s.size]
}

func (f *elfFile) defined() []string {
	var out []string
	for _, s := range f.symbols {
		if s.global() && s.defined() && s.named() {
			out = append(out, s.name)
		}
	}
	return out
}

func editELF(data []byte, e Edits) ([]byte, int, error) {
	f, err := parseELF(data)
	if err != nil {
		return nil, 0, err
	}
	if e.empty() || f.symtab == 0 {
		return data, 0, nil
	}
	wrapped := map[string]bool{}
	for _, name := range e.Wrap {
		wrapped[name] = true
	}
	renamed := map[int]string{}
	// A defined wrapped symbol keeps its definition. References to it move to
	// a __wrap_ symbol, which is reused when the object already has one.
	retarget := map[uint32]uint32{}
	var added []elfSymbol
	existing := map[string]uint32{}
	for i, s := range f.symbols {
		if s.global() && s.named() {
			if _, ok := existing[s.name]; !ok {
				existing[s.name] = uint32(i)
			}
		}
	}
	for i, s := range f.symbols {
		if i == 0 || !s.named() {
			continue
		}
		switch real, isReal := strings.CutPrefix(s.name, "__real_"); {
		case s.global() && wrapped[s.name] && !s.defined():
			renamed[i] = "__wrap_" + s.name
		case s.global() && wrapped[s.name]:
			target, ok := existing["__wrap_"+s.name]
			if !ok {
				target = uint32(len(f.symbols) + len(added))
				existing["__wrap_"+s.name] = target
				// Keep the symbol type so a wrapped function stays a function.
				added = append(added, elfSymbol{name: "__wrap_" + s.name, info: elf.ST_INFO(elf.STB_GLOBAL, elf.ST_TYPE(s.info))})
			}
			retarget[uint32(i)] = target
		case s.global() && isReal && wrapped[real] && !s.defined():
			// An undefined NAME beside a defined NAME binds to it when linked.
			renamed[i] = real
		default:
			if to, ok := e.Rename[s.name]; ok && to != s.name {
				renamed[i] = to
			}
		}
	}
	retargeted := 0
	out := bytes.Clone(data)
	if len(retarget) > 0 {
		for i, s := range f.sections {
			if s.typ == shtCREL && int(s.link) == f.symtab {
				return nil, 0, errors.New("redirecting references in CREL relocations is unsupported; wrap a symbol defined in this object without -Wa,--crel")
			}
			if s.typ != elf.SHT_RELA && s.typ != elf.SHT_REL || int(s.link) != f.symtab {
				continue
			}
			// Debug data describes the definition; only runtime references move.
			if int(s.info) >= len(f.sections) || f.sections[s.info].flags&elf.SHF_ALLOC == 0 {
				continue
			}
			size := uint64(16)
			if s.typ == elf.SHT_RELA {
				size = 24
			}
			if s.size%size != 0 {
				return nil, 0, fmt.Errorf("malformed ELF relocation section %d", i)
			}
			for off := s.offset; off < s.offset+s.size; off += size {
				info := le.Uint64(out[off+8:])
				if target, ok := retarget[uint32(info>>32)]; ok {
					le.PutUint64(out[off+8:], uint64(target)<<32|info&0xffffffff)
					retargeted++
				}
			}
		}
	}
	if len(renamed) == 0 && retargeted == 0 {
		return data, 0, nil
	}
	if retargeted == 0 {
		added = nil
	}
	// Append new names to a copy of the string table so that existing offsets,
	// including shared suffixes and section names, keep their meaning.
	symtab := f.sections[f.symtab]
	strtab := bytes.Clone(f.section(int(symtab.link)))
	offsets := map[string]uint32{}
	intern := func(name string) (uint32, error) {
		if off, ok := offsets[name]; ok {
			return off, nil
		}
		if uint64(len(strtab))+uint64(len(name)) >= 1<<32 {
			return 0, errors.New("ELF string table is too large")
		}
		off := uint32(len(strtab))
		strtab = append(append(strtab, name...), 0)
		offsets[name] = off
		return off, nil
	}
	symbols := bytes.Clone(f.data[symtab.offset : symtab.offset+symtab.size])
	for i, name := range renamed {
		off, err := intern(name)
		if err != nil {
			return nil, 0, err
		}
		le.PutUint32(symbols[i*symbolSize:], off)
	}
	for _, s := range added {
		off, err := intern(s.name)
		if err != nil {
			return nil, 0, err
		}
		entry := make([]byte, symbolSize)
		le.PutUint32(entry, off)
		entry[4] = s.info
		symbols = append(symbols, entry...)
	}
	header := func(i int) []byte { return out[f.shoff+uint64(i)*sectionHeaderSize:] }
	place := func(i int, content []byte, align int) {
		for len(out)%align != 0 {
			out = append(out, 0)
		}
		le.PutUint64(header(i)[24:], uint64(len(out)))
		le.PutUint64(header(i)[32:], uint64(len(content)))
		out = append(out, content...)
	}
	if len(added) == 0 {
		copy(out[symtab.offset:], symbols)
	} else {
		place(f.symtab, symbols, 8)
		for i, s := range f.sections {
			if s.typ == elf.SHT_SYMTAB_SHNDX && int(s.link) == f.symtab {
				// New symbols are undefined, so their extended index is zero.
				place(i, append(bytes.Clone(f.section(i)), make([]byte, 4*len(added))...), 4)
			}
		}
	}
	if len(offsets) > 0 {
		place(int(symtab.link), strtab, 1)
	}
	return out, len(renamed) + retargeted, nil
}
