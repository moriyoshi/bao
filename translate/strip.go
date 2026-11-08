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
	m, err := readImage(Object{Name: "strip-input.o", Data: data})
	if err != nil {
		return nil, 0, err
	}
	sectionMap := make([]uint8, len(m.sections)+1)
	var sections []imageSection
	count := 0
	for i, s := range m.sections {
		if s.seg == "__DWARF" || strings.HasPrefix(s.name, "__debug_") || strings.HasPrefix(s.name, "__zdebug_") {
			count++
			continue
		}
		sections = append(sections, s)
		sectionMap[i+1] = uint8(len(sections))
	}
	if count == 0 {
		stabs := false
		for _, s := range m.symbols {
			stabs = stabs || s.Type&0xe0 != 0
		}
		if !stabs {
			return append([]byte(nil), data...), 0, nil
		}
	}
	indices := make([]uint32, len(m.symbols))
	var symbols []macho.Symbol
	for i, s := range m.symbols {
		indices[i] = ^uint32(0)
		if s.Type&0xe0 != 0 {
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
				return nil, 0, fmt.Errorf("debug stripping cannot preserve scattered relocation")
			}
			if m.cpu == macho.CpuArm64 && r.Type == 10 {
				continue
			} // ARM64 ADDEND payload is not a symbol index.
			if r.Extern {
				if int(r.Value) >= len(indices) || indices[r.Value] == ^uint32(0) {
					return nil, 0, fmt.Errorf("runtime relocation references debug-only symbol")
				}
				r.Value = indices[r.Value]
			} else {
				if int(r.Value) >= len(sectionMap) || sectionMap[r.Value] == 0 {
					return nil, 0, fmt.Errorf("runtime relocation references debug-only section")
				}
				r.Value = uint32(sectionMap[r.Value])
			}
		}
	}
	m.sections = sections
	m.symbols = symbols
	b, err := m.encode()
	return b, count, err
}
