package translate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
)

func inspectAMD64(o Object, f *macho.File) (ObjectReport, []string, []string, error) {
	r := ObjectReport{Name: o.Name, Architecture: "amd64", SHA256: digest(o.Data), Relocations: map[string]int{}, Findings: []Finding{{Code: "raw-pack-profile", Detail: "amd64 requires runtime translation; raw pack is restricted to its arm64 leaf profile"}}}
	names := []string{"UNSIGNED", "SIGNED", "BRANCH", "GOT_LOAD", "GOT", "SUBTRACTOR", "SIGNED_1", "SIGNED_2", "SIGNED_4", "TLV"}
	for _, s := range f.Sections {
		r.Sections = append(r.Sections, Section{Name: s.Seg + "/" + s.Name, Size: s.Size, Align: s.Align, Flags: s.Flags, Relocs: s.Nreloc})
		for _, rel := range s.Relocs {
			name := fmt.Sprint(rel.Type)
			if int(rel.Type) < len(names) {
				name = names[rel.Type]
			}
			r.Relocations["X86_64_RELOC_"+name]++
		}
	}
	var defs, undefs []string
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if s.Type&0xe0 == 0 && s.Type&1 != 0 {
				if s.Sect == 0 {
					undefs = append(undefs, s.Name)
				} else {
					defs = append(defs, s.Name)
				}
			}
		}
	}
	return r, defs, undefs, nil
}

func lowerTLVPAMD64(f *macho.File, out []byte) ([]byte, int, error) {
	n := 0
	for _, s := range f.Sections {
		for i, r := range s.Relocs {
			if r.Type != 9 {
				continue
			}
			at := uint64(s.Offset) + uint64(r.Addr)
			if !r.Extern || r.Scattered || !r.Pcrel || r.Len != 2 || r.Addr < 3 || uint64(r.Addr)+4 > s.Size || at+4 > uint64(len(out)) || f.Symtab == nil || int(r.Value) >= len(f.Symtab.Syms) {
				return nil, 0, fmt.Errorf("unsupported amd64 TLV relocation")
			}
			sym := f.Symtab.Syms[r.Value]
			if sym.Sect == 0 || int(sym.Sect) > len(f.Sections) || f.Sections[sym.Sect-1].Flags&0xff != 0x13 {
				return nil, 0, fmt.Errorf("amd64 TLV target is not a local descriptor")
			}
			if out[at-3]&0xf8 != 0x48 || out[at-2] != 0x8b || out[at-1]&0xc7 != 0x05 {
				return nil, 0, fmt.Errorf("amd64 TLV reference is not a 64-bit RIP-relative MOV")
			}
			pos := uint64(s.Reloff) + uint64(i)*8 + 4
			if pos+4 > uint64(len(out)) {
				return nil, 0, fmt.Errorf("TLV relocation outside object")
			}
			v := binary.LittleEndian.Uint32(out[pos:])
			binary.LittleEndian.PutUint32(out[pos:], v&0x0fffffff|3<<28)
			n++
		}
	}
	return out, n, nil
}

// Give section-indexed relocations explicit symbol targets. Keep implicit
// integer addends until the ELF encoder consumes them, without ARM ADDEND tags.
func (m *objectImage) indexAMD64SectionReferences(namespace string, oi int) error {
	anchors := map[uint32]uint32{}
	for si := range m.sections {
		s := &m.sections[si]
		for ri := range s.relocs {
			r := &s.relocs[ri]
			if r.Extern {
				continue
			}
			if r.Value == 0 || int(r.Value) > len(m.sections) {
				return fmt.Errorf("invalid amd64 section relocation")
			}
			width := uint64(1) << r.Len
			if uint64(r.Addr)+width > uint64(len(s.data)) {
				return fmt.Errorf("amd64 relocation outside data")
			}
			target := m.sections[r.Value-1]
			var value int64
			if width == 8 {
				value = int64(binary.LittleEndian.Uint64(s.data[r.Addr:]))
			} else if width == 4 {
				value = int64(int32(binary.LittleEndian.Uint32(s.data[r.Addr:])))
			} else {
				return fmt.Errorf("unsupported amd64 relocation width")
			}
			if r.Type == 0 && !r.Pcrel {
				value -= int64(target.addr)
			} else if r.Pcrel && (r.Type == 1 || r.Type == 2 || r.Type >= 6 && r.Type <= 8) {
				value += int64(s.addr) + int64(r.Addr) + 4 - int64(target.addr)
			} else {
				return fmt.Errorf("unsupported amd64 local relocation type %d", r.Type)
			}
			idx, ok := anchors[r.Value]
			if !ok {
				idx = uint32(len(m.symbols))
				anchors[r.Value] = idx
				m.symbols = append(m.symbols, macho.Symbol{Name: fmt.Sprintf("_%ssection_%d_%d", namespace, oi, r.Value), Type: 0xe, Sect: uint8(r.Value), Value: target.addr})
			}
			r.Extern = true
			r.Value = idx
			if width == 8 {
				binary.LittleEndian.PutUint64(s.data[r.Addr:], uint64(value))
			} else {
				if value < -(1<<31) || value >= 1<<31 {
					return fmt.Errorf("amd64 local addend overflow")
				}
				binary.LittleEndian.PutUint32(s.data[r.Addr:], uint32(value))
			}
		}
	}
	return nil
}

// localizeAMD64GOTReferences gives X86_64_RELOC_GOT references to native-defined
// symbols an image-private pointer slot. Only a MOV can become an LEA; Go's
// linker keeps other GOT forms (CMP, ADD, LSDA fields) and binds the entry by
// name, which dyld cannot resolve because the definition is not exported.
// Personality GOT fields in __eh_frame are lowered by PrepareRuntimeMetadata.
func (m *objectImage) localizeAMD64GOTReferences(namespace string) (int, error) {
	if m.cpu != macho.CpuAmd64 {
		return 0, nil
	}
	gotIndex := -1
	slots := make(map[uint32]uint32)
	for si := 0; si < len(m.sections); si++ {
		if si == gotIndex || m.sections[si].name == "__eh_frame" {
			continue
		}
		for ri := range m.sections[si].relocs {
			r := m.sections[si].relocs[ri]
			if r.Type != 4 || !r.Extern {
				continue
			}
			if int(r.Value) >= len(m.symbols) || !r.Pcrel || r.Len != 2 {
				return 0, fmt.Errorf("unsupported amd64 GOT relocation")
			}
			if m.symbols[r.Value].Sect == 0 {
				continue
			}
			if gotIndex < 0 {
				if len(m.sections) >= 255 {
					return 0, fmt.Errorf("too many native sections for a local GOT")
				}
				gotIndex = len(m.sections)
				m.sections = append(m.sections, imageSection{name: "__bao_local_got", seg: "__DATA", addr: (m.end() + 7) &^ 7, align: 3})
			}
			slot, ok := slots[r.Value]
			if !ok {
				g := &m.sections[gotIndex]
				slot = uint32(len(m.symbols))
				m.symbols = append(m.symbols, macho.Symbol{Name: fmt.Sprintf("_%slocal_got_%d", namespace, len(slots)), Type: 0xe, Sect: uint8(gotIndex + 1), Value: g.addr + g.size})
				g.relocs = append(g.relocs, macho.Reloc{Addr: uint32(g.size), Value: r.Value, Extern: true, Len: 3})
				g.data = append(g.data, make([]byte, 8)...)
				g.size += 8
				slots[r.Value] = slot
			}
			// The implicit addend already follows SIGNED's convention, so only
			// the relocation kind and target change.
			m.sections[si].relocs[ri].Type = 1
			m.sections[si].relocs[ri].Value = slot
		}
	}
	return len(slots), nil
}

func (m *objectImage) amd64ELFRelocations(si int, data []byte, indices []uint32) ([]byte, error) {
	s := m.sections[si]
	var out bytes.Buffer
	for i := 0; i < len(s.relocs); i++ {
		r := s.relocs[i]
		width := uint64(1) << r.Len
		if !r.Extern || int(r.Value) >= len(indices) || indices[r.Value] == 0 || uint64(r.Addr)+width > uint64(len(data)) {
			return nil, fmt.Errorf("invalid amd64 relocation target/range")
		}
		var add int64
		if width == 8 {
			add = int64(binary.LittleEndian.Uint64(data[r.Addr:]))
		} else if width == 4 {
			add = int64(int32(binary.LittleEndian.Uint32(data[r.Addr:])))
		} else {
			return nil, fmt.Errorf("unsupported amd64 relocation width")
		}
		target := r.Value
		var typ elf.R_X86_64
		switch r.Type {
		case 0:
			if r.Pcrel || width != 8 {
				return nil, fmt.Errorf("unsupported amd64 absolute relocation")
			}
			typ = elf.R_X86_64_64
		case 1, 2, 6, 7, 8:
			if !r.Pcrel || width != 4 {
				return nil, fmt.Errorf("unsupported amd64 PC-relative relocation")
			}
			typ = elf.R_X86_64_PC32
			add -= 4
			// SIGNED_1/2/4 already encode their trailing-immediate adjustment
			// in the displacement. Applying it again corrupts nearby globals.
		case 3, 4:
			if !r.Pcrel || width != 4 {
				return nil, fmt.Errorf("unsupported amd64 GOT relocation")
			}
			typ = elf.R_X86_64_GOTPCREL
			add -= 4
			if r.Type == 3 && m.symbols[target].Sect != 0 {
				if r.Addr < 3 || data[r.Addr-3]&0xf8 != 0x48 || data[r.Addr-2] != 0x8b || data[r.Addr-1]&0xc7 != 0x05 {
					return nil, fmt.Errorf("local amd64 GOT load is not a RIP-relative MOV")
				}
				data[r.Addr-2] = 0x8d
				typ = elf.R_X86_64_PC32
			}
		case 5:
			if i+1 >= len(s.relocs) {
				return nil, fmt.Errorf("missing amd64 subtractor pair")
			}
			to := s.relocs[i+1]
			i++
			if to.Type != 0 || to.Addr != r.Addr || to.Len != r.Len || !to.Extern || int(to.Value) >= len(indices) || indices[to.Value] == 0 || m.symbols[r.Value].Sect != uint8(si+1) {
				return nil, fmt.Errorf("unsupported amd64 subtractor pair")
			}
			add += int64(s.addr) + int64(r.Addr) - int64(m.symbols[r.Value].Value)
			target = to.Value
			if width == 4 {
				typ = elf.R_X86_64_PC32
			} else {
				typ = elf.R_X86_64_PC64
			}
		default:
			return nil, fmt.Errorf("unsupported amd64 relocation type %d", r.Type)
		}
		clear(data[uint64(r.Addr) : uint64(r.Addr)+width])
		_ = binary.Write(&out, binary.LittleEndian, [3]uint64{uint64(r.Addr), uint64(indices[target])<<32 | uint64(typ), uint64(add)})
	}
	return out.Bytes(), nil
}

// Emit fixed-frame DWARF from public x86-64 compact encoding fields. Original
// DWARF stays preferred; augmented/frameless compact modes fail explicitly.
func (m *objectImage) synthesizeAMD64Frames(namespace string, oi int) (UnwindSection, int, error) {
	var result UnwindSection
	var data []byte
	var rels []macho.Reloc
	append32 := func(v uint32) { data = binary.LittleEndian.AppendUint32(data, v) }
	append64 := func(v uint64) { data = binary.LittleEndian.AppendUint64(data, v) }
	finish := func(start int) {
		for len(data)%8 != 0 {
			data = append(data, 0)
		}
		binary.LittleEndian.PutUint32(data[start:], uint32(len(data)-start-4))
	}
	append32(0)
	append32(0)
	data = append(data, 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0, 0x0c, 7, 8, 0x90, 1)
	finish(0)
	count := 0
	for _, s := range m.sections {
		if s.name != "__compact_unwind" || s.size == 0 {
			continue
		}
		if s.size%32 != 0 {
			return result, 0, fmt.Errorf("invalid amd64 compact record size")
		}
		byAddr := map[uint32]macho.Reloc{}
		for _, r := range s.relocs {
			if r.Type != 0 || r.Len != 3 || r.Pcrel {
				return result, 0, fmt.Errorf("unsupported amd64 compact relocation")
			}
			if _, ok := byAddr[r.Addr]; ok {
				return result, 0, fmt.Errorf("duplicate compact relocation")
			}
			byAddr[r.Addr] = r
		}
		for at := uint32(0); uint64(at) < s.size; at += 32 {
			length := binary.LittleEndian.Uint32(s.data[at+8:])
			encoding := binary.LittleEndian.Uint32(s.data[at+12:])
			mode := encoding & 0x0f000000
			if length == 0 || mode == 0x04000000 {
				continue
			}
			if mode != 0x01000000 {
				return result, 0, fmt.Errorf("unsupported amd64 compact mode %#x", mode)
			}
			_, personality := byAddr[at+16]
			_, lsda := byAddr[at+24]
			if personality || lsda || binary.LittleEndian.Uint64(s.data[at+16:]) != 0 || binary.LittleEndian.Uint64(s.data[at+24:]) != 0 || encoding&0x70000000 != 0 || encoding&^uint32(0x81ff7fff) != 0 {
				return result, 0, fmt.Errorf("unsupported amd64 compact augmentation/bits")
			}
			code, ok := byAddr[at]
			if !ok {
				return result, 0, fmt.Errorf("compact entry has no code reference")
			}
			start := len(data)
			result.FDEOffsets = append(result.FDEOffsets, uint32(start))
			append32(0)
			append32(uint32(start + 4))
			code.Addr = uint32(len(data))
			rels = append(rels, code)
			append64(binary.LittleEndian.Uint64(s.data[at:]))
			append64(uint64(length))
			data = append(data, 0, 0x0c, 6, 16, 0x86, 2)
			offset := int((encoding >> 16) & 255)
			for slot := 0; slot < 5; slot++ {
				reg := (encoding >> uint(3*slot)) & 7
				if reg == 0 {
					continue
				}
				if reg > 6 || offset <= slot {
					return result, 0, fmt.Errorf("invalid compact register slot")
				}
				dwarf := []byte{0, 3, 12, 13, 14, 15, 6}[reg]
				data = append(data, 0x80+dwarf)
				data = appendULEB(data, uint64(2+offset-slot))
			}
			finish(start)
			count++
		}
	}
	if count == 0 {
		return UnwindSection{}, 0, nil
	}
	name := fmt.Sprintf("%scompact_eh_%d", namespace, oi)
	addr := (m.end() + 7) &^ 7
	m.sections = append(m.sections, imageSection{name: "__bao_comp_eh", seg: "__DATA", addr: addr, size: uint64(len(data)), align: 3, data: data, relocs: rels})
	m.symbols = append(m.symbols, macho.Symbol{Name: "_" + name, Type: 0xf, Sect: uint8(len(m.sections)), Value: addr})
	result.Symbol = name
	return result, count, nil
}
