package translate

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
)

type UnwindSection struct {
	Symbol     string   `json:"base_symbol"`
	FDEOffsets []uint32 `json:"fde_offsets"`
}

type ConstructorTable struct {
	Symbol string `json:"base_symbol"`
	Count  uint64 `json:"count"`
}

// PrepareRuntimeMetadata preserves native DWARF records under an imported name,
// lowers their GOT references, and records FDEs for explicit libunwind
// registration. Darwin __register_frame accepts individual FDEs, not a section.
// ARM64 FRAME/FRAMELESS compact entries also receive equivalent fixed-frame
// DWARF records. Original compact bytes remain preserved in the object.
func (p *TLSProbe) PrepareRuntimeMetadata() error {
	for oi, o := range p.Objects {
		m, err := readImage(o)
		if err != nil {
			return err
		}
		for _, s := range m.symbols {
			if s.Name == "___register_frame" && s.Type&0x0e == 0x0e && s.Sect > 0 {
				p.RegisterFrame = "__register_frame"
			}
		}
		// Add local GOT slots for POINTER_TO_GOT references. Unlike an address
		// relocation, the resulting pointer must still be dereferenced by the
		// DW_EH_PE_indirect personality encoding.
		gotIndex := -1
		slots := make(map[uint32]uint32)
		for si := 0; si < len(m.sections); si++ {
			s := &m.sections[si]
			if s.name != "__eh_frame" {
				continue
			}
			if err := m.foldSectionDifferences(si); err != nil {
				return err
			}
			name := fmt.Sprintf("%seh_%d", p.Namespace, oi)
			fdes, err := frameOffsets(s.data)
			if err != nil {
				return fmt.Errorf("%s: %w", o.Name, err)
			}
			s.name = "__bao_eh_frame"
			m.symbols = append(m.symbols, macho.Symbol{Name: "_" + name, Type: 0xf, Sect: uint8(si + 1), Value: s.addr})
			p.Unwind = append(p.Unwind, UnwindSection{Symbol: name, FDEOffsets: fdes})
			var rels []macho.Reloc
			for _, r := range s.relocs {
				gotType := uint8(7)
				if m.cpu == macho.CpuAmd64 {
					gotType = 4
				}
				if r.Type != gotType {
					rels = append(rels, r)
					continue
				}
				if !r.Extern || !r.Pcrel || r.Len != 2 || int(r.Value) >= len(m.symbols) {
					return fmt.Errorf("unsupported personality GOT reference")
				}
				if m.cpu == macho.CpuAmd64 {
					if uint64(r.Addr)+4 > uint64(len(s.data)) {
						return fmt.Errorf("personality GOT field outside unwind data")
					}
					v := binary.LittleEndian.Uint32(s.data[r.Addr:])
					binary.LittleEndian.PutUint32(s.data[r.Addr:], v-4)
				}
				if gotIndex < 0 {
					gotIndex = len(m.sections)
					// Appending may move the slice. Reacquire s before use.
					m.sections = append(m.sections, imageSection{name: "__bao_unwind_got", seg: "__DATA", addr: (m.end() + 7) &^ 7, align: 3})
					s = &m.sections[si]
				}
				slot, ok := slots[r.Value]
				if !ok {
					g := &m.sections[gotIndex]
					slot = uint32(len(m.symbols))
					m.symbols = append(m.symbols, macho.Symbol{Name: fmt.Sprintf("_%sgot_%d_%d", p.Namespace, oi, len(slots)), Type: 0xf, Sect: uint8(gotIndex + 1), Value: g.addr + g.size})
					g.relocs = append(g.relocs, macho.Reloc{Addr: uint32(g.size), Value: r.Value, Extern: true, Len: 3})
					g.data = append(g.data, make([]byte, 8)...)
					g.size += 8
					slots[r.Value] = slot
				}
				from := uint32(len(m.symbols))
				m.symbols = append(m.symbols, macho.Symbol{Name: fmt.Sprintf("_%sfield_%d_%d", p.Namespace, oi, r.Addr), Type: 0xe, Sect: uint8(si + 1), Value: s.addr + uint64(r.Addr)})
				subtractor := uint8(1)
				if m.cpu == macho.CpuAmd64 {
					subtractor = 5
				}
				rels = append(rels, macho.Reloc{Addr: r.Addr, Value: from, Type: subtractor, Len: 2, Extern: true}, macho.Reloc{Addr: r.Addr, Value: slot, Len: 2, Extern: true})
			}
			s = &m.sections[si]
			s.relocs = rels
		}
		for si, s := range m.sections {
			if s.flags&0xff == 0xa && s.size != 0 {
				return fmt.Errorf("native terminator tables need an explicit shutdown policy")
			}
			if s.flags&0xff != 9 || s.size == 0 {
				continue
			}
			if s.size%8 != 0 {
				return fmt.Errorf("invalid initializer table size")
			}
			name := fmt.Sprintf("%sctors_%d_%d", p.Namespace, oi, si)
			m.symbols = append(m.symbols, macho.Symbol{Name: "_" + name, Type: 0xf, Sect: uint8(si + 1), Value: s.addr})
			p.Constructors = append(p.Constructors, ConstructorTable{Symbol: name, Count: s.size / 8})
		}
		var compact UnwindSection
		var count int
		if m.cpu == macho.CpuAmd64 {
			compact, count, err = m.synthesizeAMD64Frames(p.Namespace, oi)
		} else {
			compact, count, err = m.synthesizeCompactFrames(p.Namespace, oi)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", o.Name, err)
		}
		if count != 0 {
			p.Unwind = append(p.Unwind, compact)
			p.CompactFramesSynthesized += count
		}
		data, err := m.encode()
		if err != nil {
			return err
		}
		p.Objects[oi].Data = data
	}
	return nil
}

// ld -r may leave relocations even on the CIE-pointer field. Differences of
// symbols within the same retained section are invariant under final layout,
// so resolve those before parsing the DWARF records. This also avoids presenting
// a transient pre-relocation CIE id (commonly the integer 4) as real metadata.
func (m *objectImage) foldSectionDifferences(si int) error {
	s := &m.sections[si]
	var out []macho.Reloc
	for i := 0; i < len(s.relocs); i++ {
		r := s.relocs[i]
		subtractor := uint8(1)
		if m.cpu == macho.CpuAmd64 {
			subtractor = 5
		}
		if r.Type == subtractor && i+1 < len(s.relocs) {
			u := s.relocs[i+1]
			if u.Type != 0 || u.Addr != r.Addr || !r.Extern || !u.Extern || int(r.Value) >= len(m.symbols) || int(u.Value) >= len(m.symbols) {
				return fmt.Errorf("malformed unwind subtractor pair")
			}
			from, to := m.symbols[r.Value], m.symbols[u.Value]
			if from.Sect == uint8(si+1) && to.Sect == from.Sect {
				width := uint64(1) << r.Len
				if uint64(r.Addr)+width > uint64(len(s.data)) {
					return fmt.Errorf("unwind relocation outside section")
				}
				switch width {
				case 4:
					v := int64(to.Value) - int64(from.Value) + int64(int32(binary.LittleEndian.Uint32(s.data[r.Addr:])))
					if v < -(1<<31) || v >= 1<<31 {
						return fmt.Errorf("unwind difference overflow")
					}
					binary.LittleEndian.PutUint32(s.data[r.Addr:], uint32(v))
				case 8:
					v := to.Value - from.Value + binary.LittleEndian.Uint64(s.data[r.Addr:])
					binary.LittleEndian.PutUint64(s.data[r.Addr:], v)
				default:
					return fmt.Errorf("unsupported unwind difference width")
				}
				i++
				continue
			}
		}
		out = append(out, r)
	}
	s.relocs = out
	return nil
}

func frameOffsets(data []byte) ([]uint32, error) {
	var out []uint32
	cies := make(map[uint32]bool)
	for off := uint64(0); off < uint64(len(data)); {
		if off+4 > uint64(len(data)) {
			return nil, fmt.Errorf("truncated frame record")
		}
		n := uint64(binary.LittleEndian.Uint32(data[off:]))
		if n == 0 {
			off += 4
			continue
		} // padding/terminator between concatenated inputs
		if n == 0xffffffff || n < 4 || off+4+n > uint64(len(data)) {
			return nil, fmt.Errorf("unsupported/truncated frame record at %#x", off)
		}
		id := binary.LittleEndian.Uint32(data[off+4:])
		if id == 0 {
			cies[uint32(off)] = true
		} else {
			if uint64(id) > off+4 || !cies[uint32(off+4)-id] {
				return nil, fmt.Errorf("FDE at %#x has no preceding CIE", off)
			}
			out = append(out, uint32(off))
		}
		off += 4 + n
	}
	return out, nil
}

// NormalizeAddends converts Mach-O's implicit integer addends into the explicit
// addends that Go's ARM64 Mach-O reader actually consumes. Without this, pointer
// constants and FDE expressions can link yet refer to the wrong address.
func (p *TLSProbe) NormalizeAddends() error {
	for oi, o := range p.Objects {
		m, err := readImage(o)
		if err != nil {
			return err
		}
		if m.cpu == macho.CpuAmd64 {
			if err := m.indexAMD64SectionReferences(p.Namespace, oi); err != nil {
				return err
			}
			p.Objects[oi].Data, err = m.encode()
			if err != nil {
				return err
			}
			continue
		}
		sectionSymbols := make(map[uint32]uint32)
		for i, sym := range m.symbols {
			if sym.Sect != 0 && sym.Type&0xe0 == 0 && sym.Value == m.sections[sym.Sect-1].addr {
				sectionSymbols[uint32(sym.Sect)] = uint32(i)
			}
		}
		for si := range m.sections {
			s := &m.sections[si]
			var out []macho.Reloc
			var explicit int64
			add := func(r macho.Reloc, a int64) error {
				if a < -(1<<23) || a >= 1<<23 {
					return fmt.Errorf("native addend exceeds Go's 24-bit Mach-O representation: %d", a)
				}
				if a != 0 {
					out = append(out, macho.Reloc{Addr: r.Addr, Value: uint32(a) & 0xffffff, Type: 10, Len: 2})
					p.AddendsNormalized++
				}
				out = append(out, r)
				return nil
			}
			for i := 0; i < len(s.relocs); i++ {
				r := s.relocs[i]
				if r.Type == 10 {
					explicit += int64(int32(r.Value<<8) >> 8)
					continue
				}
				if r.Type != 0 && r.Type != 1 {
					if err := add(r, explicit); err != nil {
						return err
					}
					explicit = 0
					continue
				}
				width := uint64(1) << r.Len
				if (width != 4 && width != 8) || uint64(r.Addr)+width > uint64(len(s.data)) {
					return fmt.Errorf("integer relocation outside section data")
				}
				var implicit int64
				if width == 4 {
					implicit = int64(int32(binary.LittleEndian.Uint32(s.data[r.Addr:])))
				} else {
					implicit = int64(binary.LittleEndian.Uint64(s.data[r.Addr:]))
				}
				if r.Type == 1 {
					if i+1 >= len(s.relocs) || s.relocs[i+1].Type != 0 || s.relocs[i+1].Addr != r.Addr {
						return fmt.Errorf("malformed subtractor pair")
					}
					if err := add(r, explicit+implicit); err != nil {
						return err
					}
					i++
					out = append(out, s.relocs[i])
				} else {
					if !r.Extern {
						if r.Value == 0 || int(r.Value) > len(m.sections) {
							return fmt.Errorf("invalid section reference")
						}
						target := m.sections[r.Value-1]
						// A local unsigned relocation stores the original virtual
						// address, not a section-relative offset.
						implicit -= int64(target.addr)
						idx, ok := sectionSymbols[r.Value]
						if !ok {
							idx = uint32(len(m.symbols))
							m.symbols = append(m.symbols, macho.Symbol{Name: fmt.Sprintf("_%ssection_%d_%d", p.Namespace, oi, r.Value), Type: 0xe, Sect: uint8(r.Value), Value: target.addr})
							sectionSymbols[r.Value] = idx
						}
						r.Extern = true
						r.Value = idx
					}
					if err := add(r, explicit+implicit); err != nil {
						return err
					}
				}
				clear(s.data[uint64(r.Addr) : uint64(r.Addr)+width])
				explicit = 0
			}
			if explicit != 0 {
				return fmt.Errorf("dangling addend")
			}
			s.relocs = out
		}
		data, err := m.encode()
		if err != nil {
			return err
		}
		p.Objects[oi].Data = data
	}
	return nil
}
