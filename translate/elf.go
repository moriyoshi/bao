package translate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// ELFContainer repackages already-lowered DARWIN code for Go's ELF object
// reader, which propagates section alignment (the Mach-O reader does not).
// The final executable is still Mach-O, the calling convention remains Darwin,
// and this makes no claim of Linux ABI or ELF executable support.
func ELFContainer(o Object) ([]byte, error) {
	m, err := readImage(o)
	if err != nil {
		return nil, err
	}
	type section struct {
		name                  string
		typ                   uint32
		flags, align, entsize uint64
		link, info            uint32
		data                  []byte
		size, offset          uint64
	}
	sections := []section{{}}
	identity := digest(o.Data)[:12]
	included := make([]bool, len(m.sections))
	for i, s := range m.sections {
		include := s.seg == "__TEXT" || s.seg == "__DATA"
		included[i] = include
		flags := uint64(0)
		if include {
			flags = uint64(elf.SHF_ALLOC)
			if s.seg == "__DATA" {
				flags |= uint64(elf.SHF_WRITE)
			}
			if s.flags&0x80000400 != 0 {
				flags |= uint64(elf.SHF_EXECINSTR)
			}
		}
		typ := uint32(elf.SHT_PROGBITS)
		if s.flags&0xff == 1 {
			typ = uint32(elf.SHT_NOBITS)
		}
		sections = append(sections, section{name: fmt.Sprintf(".bao.%s.%s.%s.%d", identity, s.seg, s.name, i), typ: typ, flags: flags, align: uint64(1) << s.align, data: bytes.Clone(s.data), size: s.size})
	}
	// ELF requires all local symbols before all global symbols. Mach-O's extra
	// leading underscore is a container convention; Go's ELF reader doesn't
	// remove it, so normalize it explicitly here.
	var order []int
	for _, global := range []bool{false, true} {
		for i, s := range m.symbols {
			if s.Type&0xe0 != 0 || (s.Sect != 0 && !included[s.Sect-1]) || (s.Type&1 != 0) != global {
				continue
			}
			order = append(order, i)
		}
	}
	indices := make([]uint32, len(m.symbols))
	for i, old := range order {
		indices[old] = uint32(i + 1)
	}
	// Infer the sizes that loadmacho would normally infer. The ELF reader expects
	// them in the object symbol table instead.
	sizes := make([]uint64, len(m.symbols))
	for si, s := range m.sections {
		var syms []int
		for i, sym := range m.symbols {
			if sym.Sect == uint8(si+1) && indices[i] != 0 {
				syms = append(syms, i)
			}
		}
		sort.SliceStable(syms, func(i, j int) bool { return m.symbols[syms[i]].Value < m.symbols[syms[j]].Value })
		for i, idx := range syms {
			end := s.addr + s.size
			if i+1 < len(syms) {
				end = m.symbols[syms[i+1]].Value
			}
			if end < m.symbols[idx].Value {
				return nil, fmt.Errorf("invalid native symbol range")
			}
			sizes[idx] = end - m.symbols[idx].Value
		}
	}
	var symtab bytes.Buffer
	write := func(v any) { _ = binary.Write(&symtab, binary.LittleEndian, v) }
	write([24]byte{})
	strtab := []byte{0}
	firstGlobal := uint32(1)
	for _, idx := range order {
		s := m.symbols[idx]
		name := strings.TrimPrefix(s.Name, "_")
		nameoff := uint32(len(strtab))
		strtab = append(strtab, name...)
		strtab = append(strtab, 0)
		bind := uint8(elf.STB_LOCAL)
		if s.Type&1 != 0 {
			bind = uint8(elf.STB_GLOBAL)
			if s.Desc&0xc0 != 0 {
				bind = uint8(elf.STB_WEAK)
			}
		} else {
			firstGlobal++
		}
		typ := uint8(elf.STT_NOTYPE)
		value := uint64(0)
		if s.Sect != 0 {
			sec := m.sections[s.Sect-1]
			value = s.Value - sec.addr
			typ = uint8(elf.STT_OBJECT)
			if sec.flags&0x80000400 != 0 {
				typ = uint8(elf.STT_FUNC)
			}
		}
		write(nameoff)
		write(bind<<4 | typ)
		write(uint8(0))
		write(uint16(s.Sect))
		write(value)
		write(sizes[idx])
	}
	symIndex := uint32(len(sections))
	strIndex := symIndex + 1
	sections = append(sections, section{name: ".symtab", typ: uint32(elf.SHT_SYMTAB), align: 8, entsize: 24, link: strIndex, info: firstGlobal, data: symtab.Bytes(), size: uint64(symtab.Len())})
	sections = append(sections, section{name: ".strtab", typ: uint32(elf.SHT_STRTAB), align: 1, data: strtab, size: uint64(len(strtab))})
	for si, s := range m.sections {
		if !included[si] || len(s.relocs) == 0 {
			continue
		}
		var rela bytes.Buffer
		if m.cpu == macho.CpuAmd64 {
			rels, err := m.amd64ELFRelocations(si, sections[si+1].data, indices)
			if err != nil {
				return nil, err
			}
			sections = append(sections, section{name: fmt.Sprintf(".rela.bao.%d", si), typ: uint32(elf.SHT_RELA), align: 8, entsize: 24, link: symIndex, info: uint32(si + 1), data: rels, size: uint64(len(rels))})
			continue
		}
		addRel := func(off uint32, symbol uint32, typ elf.R_AARCH64, addend int64) error {
			if int(symbol) >= len(indices) || indices[symbol] == 0 {
				return fmt.Errorf("native relocation targets an ignored definition")
			}
			_ = binary.Write(&rela, binary.LittleEndian, [3]uint64{uint64(off), uint64(indices[symbol])<<32 | uint64(typ), uint64(addend)})
			return nil
		}
		var addend int64
		for i := 0; i < len(s.relocs); i++ {
			r := s.relocs[i]
			if r.Type == 10 {
				addend += int64(int32(r.Value<<8) >> 8)
				continue
			}
			if !r.Extern {
				return nil, fmt.Errorf("ELF container needs indexed symbols for native section references")
			}
			target := r.Value
			var typ elf.R_AARCH64
			switch r.Type {
			case 0:
				if r.Len != 3 {
					return nil, fmt.Errorf("unsupported native absolute relocation width")
				}
				typ = elf.R_AARCH64_ABS64
			case 1:
				if i+1 >= len(s.relocs) {
					return nil, fmt.Errorf("missing native subtractor pair")
				}
				to := s.relocs[i+1]
				i++
				if to.Type != 0 || to.Addr != r.Addr || !to.Extern || m.symbols[r.Value].Sect != uint8(si+1) {
					return nil, fmt.Errorf("unsupported cross-section subtractor")
				}
				addend += int64(s.addr) + int64(r.Addr) - int64(m.symbols[r.Value].Value)
				target = to.Value
				if r.Len == 2 {
					typ = elf.R_AARCH64_PREL32
				} else if r.Len == 3 {
					typ = elf.R_AARCH64_PREL64
				} else {
					return nil, fmt.Errorf("unsupported subtractor width")
				}
			case 2:
				typ = elf.R_AARCH64_CALL26
				if binary.LittleEndian.Uint32(s.data[r.Addr:])&0xfc000000 == 0x14000000 {
					typ = elf.R_AARCH64_JUMP26
				}
			case 3:
				typ = elf.R_AARCH64_ADR_PREL_PG_HI21
			case 4:
				ins := binary.LittleEndian.Uint32(s.data[r.Addr:])
				if ins&0x7f000000 == 0x11000000 {
					typ = elf.R_AARCH64_ADD_ABS_LO12_NC
				} else {
					scale := ins >> 30
					if ins&0x04800000 == 0x04800000 {
						scale = 4
					}
					typ = []elf.R_AARCH64{elf.R_AARCH64_LDST8_ABS_LO12_NC, elf.R_AARCH64_LDST16_ABS_LO12_NC, elf.R_AARCH64_LDST32_ABS_LO12_NC, elf.R_AARCH64_LDST64_ABS_LO12_NC, elf.R_AARCH64_LDST128_ABS_LO12_NC}[scale]
				}
			case 5, 6:
				// Preserve dynamic imports through Go's GOT. For a native local
				// target, perform the same ADRP/LDR -> ADRP/ADD relaxation as
				// Go's Mach-O reader so locals need no dynamic symbol export.
				local := m.symbols[target].Sect != 0
				if r.Type == 5 {
					typ = elf.R_AARCH64_ADR_GOT_PAGE
					if local {
						typ = elf.R_AARCH64_ADR_PREL_PG_HI21
					}
				} else {
					typ = elf.R_AARCH64_LD64_GOT_LO12_NC
					if local {
						ins := binary.LittleEndian.Uint32(s.data[r.Addr:])
						if ins>>24 != 0xf9 {
							return nil, fmt.Errorf("unexpected native local GOT instruction")
						}
						binary.LittleEndian.PutUint32(sections[si+1].data[r.Addr:], 0x91000000|ins&0x003fffff)
						typ = elf.R_AARCH64_ADD_ABS_LO12_NC
					}
				}
			default:
				return nil, fmt.Errorf("unsupported native relocation %s in ELF container", relocName(r.Type))
			}
			if err := addRel(r.Addr, target, typ, addend); err != nil {
				return nil, err
			}
			addend = 0
		}
		if addend != 0 {
			return nil, fmt.Errorf("dangling native addend")
		}
		sections = append(sections, section{name: fmt.Sprintf(".rela.bao.%d", si), typ: uint32(elf.SHT_RELA), align: 8, entsize: 24, link: symIndex, info: uint32(si + 1), data: rela.Bytes(), size: uint64(rela.Len())})
	}
	shstr := []byte{0}
	nameoffs := make([]uint32, len(sections)+1)
	sections = append(sections, section{name: ".shstrtab", typ: uint32(elf.SHT_STRTAB), align: 1})
	for i, s := range sections {
		nameoffs[i] = uint32(len(shstr))
		shstr = append(shstr, s.name...)
		shstr = append(shstr, 0)
	}
	sections[len(sections)-1].data = shstr
	sections[len(sections)-1].size = uint64(len(shstr))
	var out bytes.Buffer
	out.Write(make([]byte, 64))
	for i := 1; i < len(sections); i++ {
		s := &sections[i]
		for uint64(out.Len())%s.align != 0 {
			out.WriteByte(0)
		}
		s.offset = uint64(out.Len())
		if s.typ != uint32(elf.SHT_NOBITS) {
			out.Write(s.data)
		}
	}
	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	shoff := uint64(out.Len())
	for i, s := range sections {
		_ = binary.Write(&out, binary.LittleEndian, struct {
			Name, Type                uint32
			Flags, Addr, Offset, Size uint64
			Link, Info                uint32
			Align, Entsize            uint64
		}{nameoffs[i], s.typ, s.flags, 0, s.offset, s.size, s.link, s.info, s.align, s.entsize})
	}
	b := out.Bytes()
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_REL))
	machine := elf.EM_AARCH64
	if m.cpu == macho.CpuAmd64 {
		machine = elf.EM_X86_64
	}
	binary.LittleEndian.PutUint16(b[18:], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[40:], shoff)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[58:], 64)
	binary.LittleEndian.PutUint16(b[60:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(b[62:], uint16(len(sections)-1))
	return b, nil
}
