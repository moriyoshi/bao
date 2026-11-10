package translate

import (
	"debug/macho"
	"fmt"
	"strings"
)

// StripDebug removes native debug sections and STABS, keeping native exception
// and compact-unwind metadata. Source bytes and native virtual addresses stay
// unchanged; section and indexed-symbol references are rebuilt consistently.
func StripDebug(data []byte) ([]byte, int, error) {
	b, count, _, err := stripSections(data, "debug", func(s imageSection) bool {
		return s.seg == "__DWARF" || strings.HasPrefix(s.name, "__debug_") || strings.HasPrefix(s.name, "__zdebug_")
	}, true)
	return b, count, err
}

// StripBitcode removes the __LLVM segment (embedded bitcode, its command line
// and module assembly), its relocations and the symbols defined in it. Go's
// linker never loads these sections. A relocation from a retained section into
// the segment fails instead of being left dangling. It returns the number of
// removed sections and their payload bytes.
func StripBitcode(data []byte) ([]byte, int, uint64, error) {
	return stripSections(data, "LLVM bitcode", func(s imageSection) bool { return s.seg == "__LLVM" }, false)
}

func stripSections(data []byte, what string, drop func(imageSection) bool, stabs bool) ([]byte, int, uint64, error) {
	m, err := readImage(Object{Name: "strip-input.o", Data: data})
	if err != nil {
		return nil, 0, 0, err
	}
	sectionMap := make([]uint8, len(m.sections)+1)
	var sections []imageSection
	count := 0
	size := uint64(0)
	for i, s := range m.sections {
		if drop(s) {
			count++
			size += s.size
			continue
		}
		sections = append(sections, s)
		sectionMap[i+1] = uint8(len(sections))
	}
	if count == 0 {
		found := false
		for _, s := range m.symbols {
			found = found || stabs && s.Type&0xe0 != 0
		}
		if !found {
			return append([]byte(nil), data...), 0, 0, nil
		}
	}
	indices := make([]uint32, len(m.symbols))
	var symbols []macho.Symbol
	for i, s := range m.symbols {
		indices[i] = ^uint32(0)
		if stabs && s.Type&0xe0 != 0 {
			continue
		}
		if s.Sect != 0 {
			if sectionMap[s.Sect] == 0 {
				continue
			}
			s.Sect = sectionMap[s.Sect]
		}
		indices[i] = uint32(len(symbols))
		symbols = append(symbols, s)
	}
	for si := range sections {
		for ri := range sections[si].relocs {
			r := &sections[si].relocs[ri]
			if r.Scattered {
				return nil, 0, 0, fmt.Errorf("%s stripping cannot preserve scattered relocation", what)
			}
			if m.cpu == macho.CpuArm64 && r.Type == 10 {
				continue
			} // ARM64 ADDEND payload is not a symbol index.
			if r.Extern {
				if int(r.Value) >= len(indices) || indices[r.Value] == ^uint32(0) {
					return nil, 0, 0, fmt.Errorf("runtime relocation in %s/%s at %#x references a %s-only symbol", sections[si].seg, sections[si].name, r.Addr, what)
				}
				r.Value = indices[r.Value]
			} else {
				if int(r.Value) >= len(sectionMap) || sectionMap[r.Value] == 0 {
					return nil, 0, 0, fmt.Errorf("runtime relocation in %s/%s at %#x references a %s section", sections[si].seg, sections[si].name, r.Addr, what)
				}
				r.Value = uint32(sectionMap[r.Value])
			}
		}
	}
	m.sections = sections
	m.symbols = symbols
	b, err := m.encode()
	return b, count, size, err
}
