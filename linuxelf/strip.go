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
	b, count, _, err := stripSections(input, "debug", elfDebugSection, true)
	return b, count, err
}

// StripBitcode removes embedded LLVM bitcode (.llvmbc) and its command line
// (.llvmcmd), their relocations and the symbols defined in them. A runtime
// relocation into them fails instead of being left dangling. It returns the
// number of removed payload sections and their bytes.
func StripBitcode(input []byte) ([]byte, int, uint64, error) {
	return stripSections(input, "LLVM bitcode", elfBitcodeSection, false)
}

func stripSections(input []byte, what string, drop func(string) bool, debug bool) ([]byte, int, uint64, error) {
	m, err := parse(input)
	if err != nil {
		return nil, 0, 0, err
	}
	removed := make([]bool, len(m.sections))
	count := 0
	size := uint64(0)
	for i, s := range m.sections {
		if drop(s.name) {
			if s.flags&elf.SHF_ALLOC != 0 {
				return nil, 0, 0, fmt.Errorf("refusing to strip allocated runtime section %s", s.name)
			}
			removed[i] = true
			count++
			size += s.size
		}
	}
	payloads := count
	for i, s := range m.sections {
		if (s.typ == elf.SHT_RELA || s.typ == elf.SHT_REL) && int(s.info) < len(removed) && removed[s.info] {
			removed[i] = true
			count++
		}
	}
	fileSymbols := false
	for _, s := range m.symbols {
		fileSymbols = fileSymbols || debug && elf.ST_TYPE(s.info) == elf.STT_FILE
	}
	if count == 0 && !fileSymbols {
		return bytes.Clone(input), 0, 0, nil
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
		if debug && elf.ST_TYPE(s.info) == elf.STT_FILE {
			continue
		}
		if s.sect != 0 && s.sect < uint16(elf.SHN_LORESERVE) {
			if int(s.sect) >= len(removed) {
				return nil, 0, 0, fmt.Errorf("%s strip: invalid native symbol section", what)
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
				return nil, 0, 0, fmt.Errorf("runtime section %s references a %s-only symbol", s.name, what)
			}
			r.sym = symIndices[r.sym]
		}
	}
	m.sections = sections
	m.symbols = symbols
	m.anchors = nil
	result, err := m.encode()
	if err != nil {
		return nil, 0, 0, err
	}
	if !debug {
		count = payloads
	}
	return result, count, size, nil
}

func elfDebugSection(name string) bool {
	return strings.HasPrefix(name, ".debug") || strings.HasPrefix(name, ".zdebug") || strings.HasPrefix(name, ".stab") || strings.HasPrefix(name, ".apple_") || name == ".gdb_index" || name == ".gnu_debuglink" || name == ".gnu_debugaltlink" || name == ".gnu_debugdata"
}

func elfBitcodeSection(name string) bool {
	return name == ".llvmbc" || name == ".llvmcmd"
}
