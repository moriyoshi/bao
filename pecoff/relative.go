package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// Stock Go does not consume ARM64 REL32. LLVM's constant relative-pointer
// tables can be resolved at build time by retaining their read-only data in
// one section. Code, writable data and cross-object targets remain unsupported.
func (o *object) lowerReadOnlyREL32() error {
	if o.machine != pe.IMAGE_FILE_MACHINE_ARM64 {
		return nil
	}
	found := false
	for _, s := range o.sections {
		for _, r := range s.relocs {
			found = found || r.Type == 17
		}
	}
	if !found {
		return nil
	}
	eligible := func(s section) bool {
		return s.name == ".rdata" && s.flags&pe.IMAGE_SCN_MEM_READ != 0 && s.flags&(pe.IMAGE_SCN_MEM_WRITE|pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_DISCARDABLE) == 0 && len(s.data) == int(s.size)
	}
	offsets := make(map[int]uint32)
	first, alignment := -1, uint32(1)
	var merged section
	for i, s := range o.sections {
		if !eligible(s) {
			continue
		}
		a := uint32(1)
		if n := s.flags >> 20 & 15; n > 0 {
			a = 1 << (n - 1)
		}
		if a > 32 {
			return fmt.Errorf("ARM64 relative data requires unsupported alignment %d", a)
		}
		if a > alignment {
			alignment = a
		}
		start := (uint64(len(merged.data)) + uint64(a) - 1) &^ (uint64(a) - 1)
		if start+uint64(s.size) > 64<<20 {
			return fmt.Errorf("ARM64 relative data exceeds 64 MiB")
		}
		if first < 0 {
			first = i
		}
		offsets[i] = uint32(start)
		merged.data = append(merged.data, make([]byte, int(start)-len(merged.data))...)
		merged.data = append(merged.data, s.data...)
	}
	for i, s := range o.sections {
		for ri, r := range s.relocs {
			if r.Type != 17 {
				continue
			}
			site, ok := offsets[i]
			if !ok || uint64(r.VirtualAddress)+4 > uint64(len(s.data)) || int(r.SymbolTableIndex) >= len(o.symbols) {
				return fmt.Errorf("unsupported/out-of-bounds ARM64 read-only REL32")
			}
			for rj, other := range s.relocs {
				if rj == ri {
					continue
				}
				width := uint64(4)
				if other.Type == 14 {
					width = 8
				}
				if uint64(other.VirtualAddress) < uint64(r.VirtualAddress)+4 && uint64(r.VirtualAddress) < uint64(other.VirtualAddress)+width {
					return fmt.Errorf("overlapping ARM64 read-only REL32 relocations")
				}
			}
			sym := o.symbols[r.SymbolTableIndex]
			target, ok := offsets[int(sym.SectionNumber)-1]
			if !ok || sym.SectionNumber <= 0 || sym.Value > o.sections[sym.SectionNumber-1].size {
				return fmt.Errorf("ARM64 read-only REL32 requires a same-object read-only target")
			}
			addend := int64(int32(binary.LittleEndian.Uint32(s.data[r.VirtualAddress:])))
			value := int64(target) + int64(sym.Value) + addend - int64(site) - int64(r.VirtualAddress) - 4
			if value < -1<<31 || value > 1<<31-1 {
				return fmt.Errorf("ARM64 read-only REL32 overflows int32")
			}
			binary.LittleEndian.PutUint32(merged.data[site+r.VirtualAddress:], uint32(value))
		}
	}
	for i := 0; i < len(o.symbols); {
		s := &o.symbols[i]
		if offset, ok := offsets[int(s.SectionNumber)-1]; ok && s.SectionNumber > 0 {
			if s.Value > o.sections[s.SectionNumber-1].size {
				return fmt.Errorf("ARM64 relative data symbol lies outside its section")
			}
			s.Value += offset
			s.SectionNumber = int16(first + 1)
		}
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	for i, s := range o.sections {
		if offset, ok := offsets[i]; ok {
			for _, r := range s.relocs {
				if r.Type != 17 {
					r.VirtualAddress += offset
					merged.relocs = append(merged.relocs, r)
				}
			}
			o.sections[i] = section{name: ".bao.drop", flags: pe.IMAGE_SCN_MEM_DISCARDABLE}
		}
	}
	merged.name = ".rdata"
	merged.size = uint32(len(merged.data))
	merged.flags = pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ
	for a := alignment; a > 0; a >>= 1 {
		merged.flags += 1 << 20
	}
	o.sections[first] = merged
	return nil
}
