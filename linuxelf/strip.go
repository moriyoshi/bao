package linuxelf

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
)

// StripDebug removes source-level DWARF sections and their symbols from a
// supported native ELF relocatable object. Runtime unwind/exception tables,
// TLS, constructors, native code and data remain intact. The input is immutable.
// Like the translator's encoder, this targets Go's object reader; discarded
// archive/group/debug indexing metadata is not an external-linker interchange.
func StripDebug(input []byte) ([]byte, int, error) {
	m, err := parse(input)
	if err != nil {
		return nil, 0, err
	}
	removed := make([]bool, len(m.sections))
	count := 0
	for i, s := range m.sections {
		if elfDebugSection(s.name) {
			if s.flags&elf.SHF_ALLOC != 0 {
				return nil, 0, fmt.Errorf("refusing to strip allocated runtime section %s", s.name)
			}
			removed[i] = true
			count++
		}
	}
	for i, s := range m.sections {
		if (s.typ == elf.SHT_RELA || s.typ == elf.SHT_REL) && int(s.info) < len(removed) && removed[s.info] {
			removed[i] = true
			count++
		}
	}
	fileSymbols := false
	for _, s := range m.symbols {
		fileSymbols = fileSymbols || elf.ST_TYPE(s.info) == elf.STT_FILE
	}
	if count == 0 && !fileSymbols {
		return bytes.Clone(input), 0, nil
	}
	// These symbol/section-index tables are rebuilt by encode. LLVM address
	// significance and COMDAT group metadata have no role in Go's object reader.
	for i, s := range m.sections {
		if s.typ == elf.SHT_SYMTAB || s.typ == elf.SHT_STRTAB || s.typ == elf.SHT_RELA || s.typ == elf.SHT_REL || s.typ == elf.SHT_GROUP || s.name == ".llvm_addrsig" {
			removed[i] = true
		}
	}
	sections := []section{{}}
	indices := make([]uint16, len(m.sections))
	for i := 1; i < len(m.sections); i++ {
		if !removed[i] {
			indices[i] = uint16(len(sections))
			sections = append(sections, m.sections[i])
		}
	}
	symbols := []symbol{{}}
	symIndices := make([]uint32, len(m.symbols))
	for i := 1; i < len(m.symbols); i++ {
		s := m.symbols[i]
		if elf.ST_TYPE(s.info) == elf.STT_FILE {
			continue
		}
		if s.sect != 0 && s.sect < uint16(elf.SHN_LORESERVE) {
			if int(s.sect) >= len(removed) {
				return nil, 0, fmt.Errorf("debug strip: invalid native symbol section")
			}
			if removed[s.sect] {
				continue
			}
			s.sect = indices[s.sect]
		}
		symIndices[i] = uint32(len(symbols))
		symbols = append(symbols, s)
	}
	for si := 1; si < len(sections); si++ {
		s := &sections[si]
		if int(s.link) < len(indices) {
			s.link = uint32(indices[s.link])
		}
		for ri := range s.relocs {
			r := &s.relocs[ri]
			if r.sym != 0 && symIndices[r.sym] == 0 {
				return nil, 0, fmt.Errorf("runtime section %s references a debug-only symbol", s.name)
			}
			r.sym = symIndices[r.sym]
		}
	}
	m.sections = sections
	m.symbols = symbols
	m.anchors = nil
	result, err := m.encode()
	if err != nil {
		return nil, 0, err
	}
	return result, count, nil
}

func elfDebugSection(name string) bool {
	return strings.HasPrefix(name, ".debug") || strings.HasPrefix(name, ".zdebug") || strings.HasPrefix(name, ".stab") || strings.HasPrefix(name, ".apple_") || name == ".gdb_index" || name == ".gnu_debuglink" || name == ".gnu_debugaltlink" || name == ".gnu_debugdata"
}
