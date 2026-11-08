package translate

import (
	"fmt"
	"strings"
)

// Mach-O relocations identify local symbols by TABLE INDEX, so ld -r may retain
// thousands of same-named locals at different addresses (notably LLVM's
// __MergedGlobals and GCC_except_tableN). Go instead interns names per object.
// Give every local definition a distinct name before Go sees the combined file.
// Relocation indices, native addresses and native payload bytes do not change.
func (m *objectImage) uniquifyLocals(namespace string) int {
	n := 0
	for i := range m.symbols {
		s := &m.symbols[i]
		if s.Type&0xe0 != 0 || s.Type&1 != 0 || s.Sect == 0 {
			continue
		}
		s.Name = fmt.Sprintf("_%slocal_%d", namespace, i)
		n++
	}
	return n
}

// mergeExecutableText keeps native startup code executable. Go classifies only
// __TEXT/__text as STEXT; importing __text_startup as read-only data also places
// its 4-byte-sized instruction stream before Go's only-4-aligned Mach-O GOT.
// Adjacent native text, including section-alignment padding, can be merged
// without moving any virtual address. Never absorb an intervening section.
func (m *objectImage) mergeExecutableText() (int, error) {
	primary := -1
	for i, s := range m.sections {
		if s.seg == "__TEXT" && s.name == "__text" {
			if primary >= 0 {
				return 0, fmt.Errorf("multiple primary text sections")
			}
			primary = i
		}
	}
	if primary < 0 {
		return 0, fmt.Errorf("no primary native text section")
	}
	removed := make(map[int]bool)
	for i, s := range m.sections {
		if i == primary || s.seg != "__TEXT" || s.flags&0x80000400 == 0 || s.size == 0 {
			continue
		}
		p := &m.sections[primary]
		end := p.addr + p.size
		if s.align > 31 || end < p.addr || s.addr < end {
			return 0, fmt.Errorf("additional native text section %s is not contiguous", s.name)
		}
		mask := uint64(1)<<s.align - 1
		if end+mask < end || s.addr != (end+mask)&^mask {
			return 0, fmt.Errorf("additional native text section %s is not contiguous", s.name)
		}
		for j, other := range m.sections {
			if j != primary && j != i && other.size != 0 && other.addr < s.addr && other.addr+other.size > end {
				return 0, fmt.Errorf("additional native text section %s crosses intervening section %s", s.name, other.name)
			}
		}
		offset := s.addr - p.addr
		if offset > uint64(^uint32(0)) {
			return 0, fmt.Errorf("merged text exceeds Mach-O relocation offset range")
		}
		p.data = append(p.data, make([]byte, s.addr-end)...)
		p.data = append(p.data, s.data...)
		p.size = offset + s.size
		p.align = max(p.align, s.align)
		for _, r := range s.relocs {
			r.Addr += uint32(offset)
			p.relocs = append(p.relocs, r)
		}
		removed[i] = true
	}
	if len(removed) == 0 {
		return 0, nil
	}
	newIndex := make([]uint8, len(m.sections))
	n := uint8(0)
	for i := range m.sections {
		if !removed[i] {
			n++
			newIndex[i] = n
		}
	}
	for i := range removed {
		newIndex[i] = newIndex[primary]
	}
	for i := range m.symbols {
		s := &m.symbols[i]
		if s.Sect != 0 {
			if int(s.Sect) > len(newIndex) {
				return 0, fmt.Errorf("invalid symbol section")
			}
			s.Sect = newIndex[s.Sect-1]
		}
	}
	for i := range m.sections {
		for j := range m.sections[i].relocs {
			r := &m.sections[i].relocs[j]
			if r.Extern || r.Type == 10 {
				continue
			}
			if r.Value == 0 || int(r.Value) > len(newIndex) {
				return 0, fmt.Errorf("invalid relocation section")
			}
			r.Value = uint32(newIndex[r.Value-1])
		}
	}
	sections := m.sections[:0]
	for i, s := range m.sections {
		if !removed[i] {
			sections = append(sections, s)
		}
	}
	m.sections = sections
	return len(removed), nil
}

// synthesizeBoundaries implements the native linker's section$start/end pseudo
// symbols without changing the arrays they delimit. It does not run ctors.
func (m *objectImage) synthesizeBoundaries() int {
	n := 0
	for i := range m.symbols {
		s := &m.symbols[i]
		if s.Sect != 0 {
			continue
		}
		parts := strings.Split(s.Name, "$")
		if len(parts) != 4 || parts[0] != "section" || (parts[1] != "start" && parts[1] != "end") {
			continue
		}
		for j, section := range m.sections {
			if section.seg == parts[2] && section.name == parts[3] {
				s.Type = 0xf
				s.Sect = uint8(j + 1)
				s.Value = section.addr
				s.Desc = 0
				if parts[1] == "end" {
					s.Value += section.size
				}
				n++
				break
			}
		}
	}
	return n
}

// coalesceTextAliases retains one representative of redundant Rust/private text
// symbols at IDENTICAL addresses, rewriting every object relocation to it. It
// never merges distinct code locations, changes native instructions, or drops
// externally named C API symbols. A consumer requesting a Rust symbol can keep
// that name explicitly. Redundant aliases otherwise overflow Go's findfunc table.
func (m *objectImage) coalesceTextAliases(keep map[string]bool) (int, error) {
	type location struct {
		section uint8
		value   uint64
	}
	groups := make(map[location][]int)
	public := func(i int) bool {
		s := m.symbols[i]
		return keep[s.Name] || s.Type&1 != 0 && !strings.HasPrefix(s.Name, "__R") && !strings.HasPrefix(s.Name, "__ZN")
	}
	for i, s := range m.symbols {
		if s.Type&0xe0 != 0 || s.Sect == 0 || int(s.Sect) > len(m.sections) {
			continue
		}
		section := m.sections[s.Sect-1]
		if section.seg == "__TEXT" && section.name == "__text" {
			groups[location{s.Sect, s.Value}] = append(groups[location{s.Sect, s.Value}], i)
		}
	}
	representative := make([]int, len(m.symbols))
	for i := range representative {
		representative[i] = i
	}
	for _, indices := range groups {
		canonical := indices[0]
		for _, i := range indices {
			if public(i) {
				canonical = i
				break
			}
			if m.symbols[i].Type&1 != 0 && m.symbols[i].Desc&0xc0 == 0 {
				canonical = i
			}
		}
		for _, i := range indices {
			if i != canonical && !public(i) {
				representative[i] = canonical
			}
		}
	}
	newIndex := make([]uint32, len(m.symbols))
	symbols := m.symbols[:0]
	for i, s := range m.symbols {
		if representative[i] == i {
			newIndex[i] = uint32(len(symbols))
			symbols = append(symbols, s)
		}
	}
	for i := range m.sections {
		for j := range m.sections[i].relocs {
			r := &m.sections[i].relocs[j]
			if !r.Extern || r.Type == 10 {
				continue
			}
			if int(r.Value) >= len(representative) {
				return 0, fmt.Errorf("invalid symbol index while coalescing text aliases")
			}
			r.Value = newIndex[representative[r.Value]]
		}
	}
	removed := len(m.symbols) - len(symbols)
	m.symbols = symbols
	return removed, nil
}
