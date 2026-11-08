package translate

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// synthesizeCompactFrames translates the Darwin arm64 FRAME/FRAMELESS encodings
// to equivalent fixed-frame DWARF CFI. Original DWARF is registered first and
// remains preferred. DWARF-mode entries keep their original records. The
// original compact table is retained intact as build provenance.
//
// Encoding/layout facts come from the SDK's public compact_unwind_encoding.h;
// this is original code, not a copied libunwind implementation.
func (m *objectImage) synthesizeCompactFrames(namespace string, oi int) (UnwindSection, int, error) {
	var result UnwindSection
	var data []byte
	var relocs []macho.Reloc
	append32 := func(v uint32) { data = binary.LittleEndian.AppendUint32(data, v) }
	append64 := func(v uint64) { data = binary.LittleEndian.AppendUint64(data, v) }
	finish := func(start int) {
		for len(data)%8 != 0 {
			data = append(data, 0)
		}
		binary.LittleEndian.PutUint32(data[start:], uint32(len(data)-start-4))
	}
	// CIE: zR, native 8-byte absolute pointers, data alignment -8, LR = r30.
	append32(0)
	append32(0)
	data = append(data, 1, 'z', 'R', 0, 1, 0x78, 30, 1, 0, 0x0c, 31, 0, 0x08, 30)
	finish(0)
	count := 0
	for _, s := range m.sections {
		if s.name != "__compact_unwind" || s.size == 0 {
			continue
		}
		if s.size%32 != 0 {
			return result, 0, fmt.Errorf("invalid arm64 compact unwind record size")
		}
		byAddr := make(map[uint32]macho.Reloc)
		for _, r := range s.relocs {
			if r.Type != 0 || r.Len != 3 || r.Pcrel {
				return result, 0, fmt.Errorf("unsupported compact unwind relocation")
			}
			if _, ok := byAddr[r.Addr]; ok {
				return result, 0, fmt.Errorf("duplicate compact unwind relocation")
			}
			byAddr[r.Addr] = r
		}
		for at := uint32(0); uint64(at) < s.size; at += 32 {
			length := binary.LittleEndian.Uint32(s.data[at+8:])
			encoding := binary.LittleEndian.Uint32(s.data[at+12:])
			mode := encoding & 0x0f000000
			if length == 0 {
				continue
			}
			if mode == 0x03000000 {
				continue
			} // Original full DWARF is retained.
			if mode != 0x02000000 && mode != 0x04000000 {
				return result, 0, fmt.Errorf("unsupported arm64 compact mode %#x", mode)
			}
			_, hasPersonality := byAddr[at+16]
			_, hasLSDA := byAddr[at+24]
			if hasPersonality || hasLSDA || binary.LittleEndian.Uint64(s.data[at+16:]) != 0 || binary.LittleEndian.Uint64(s.data[at+24:]) != 0 || encoding&0x70000000 != 0 {
				return result, 0, fmt.Errorf("compact frame with personality/LSDA needs a dedicated augmented CIE")
			}
			mask := uint32(0x8f000f1f)
			if mode == 0x02000000 {
				mask |= 0x00fff000
			}
			if encoding&^mask != 0 {
				return result, 0, fmt.Errorf("unknown compact frame bits %#x", encoding&^mask)
			}
			code, ok := byAddr[at]
			if !ok {
				return result, 0, fmt.Errorf("compact frame has no code relocation")
			}
			start := len(data)
			result.FDEOffsets = append(result.FDEOffsets, uint32(start))
			append32(0)
			append32(uint32(start + 4))
			code.Addr = uint32(len(data))
			relocs = append(relocs, code)
			append64(binary.LittleEndian.Uint64(s.data[at:]))
			append64(uint64(length))
			data = append(data, 0)  // FDE augmentation length
			nextOffset := uint64(3) // x19 at CFA-24, x20 at CFA-32, etc.
			if mode == 0x04000000 {
				data = append(data, 0x0c, 29, 16, 0x9d, 2, 0x9e, 1) // CFA=FP+16, saved FP/LR
			} else {
				stackSize := uint64((encoding&0x00fff000)>>12) * 16
				if stackSize < uint64(bits.OnesCount32(encoding&0xf1f))*16 {
					return result, 0, fmt.Errorf("frameless stack cannot contain its saved register pairs")
				}
				data = append(data, 0x0c, 31)
				data = appendULEB(data, stackSize)
				nextOffset = 1
			}
			for i, flag := range []uint32{1, 2, 4, 8, 16, 0x100, 0x200, 0x400, 0x800} {
				if encoding&flag == 0 {
					continue
				}
				reg := uint64(19 + 2*i)
				if i >= 5 {
					reg = uint64(72 + 2*(i-5))
				} // DWARF d8..d15 register numbers
				for j := uint64(0); j < 2; j++ {
					if reg+j < 64 {
						data = append(data, byte(0x80+reg+j))
					} else {
						data = append(data, 5)
						data = appendULEB(data, reg+j)
					}
					data = appendULEB(data, nextOffset)
					nextOffset++
				}
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
	m.sections = append(m.sections, imageSection{name: "__bao_comp_eh", seg: "__DATA", addr: addr, size: uint64(len(data)), align: 3, data: data, relocs: relocs})
	m.symbols = append(m.symbols, macho.Symbol{Name: "_" + name, Type: 0xf, Sect: uint8(len(m.sections)), Value: addr})
	result.Symbol = name
	return result, count, nil
}

func appendULEB(b []byte, n uint64) []byte {
	for {
		v := byte(n & 127)
		n >>= 7
		if n != 0 {
			v |= 128
		}
		b = append(b, v)
		if n == 0 {
			return b
		}
	}
}
