package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// Null weak addresses must stay null. A native data definition at an address
// containing zero would change function-pointer tests. Unreachable direct calls
// use a private null tail jump, avoiding an out-of-range PE REL32 to address zero.
func (o *object) resolveWeakZeros(zeros map[uint32]bool) error {
	type site struct{ section, reloc int }
	var calls []site
	for si := range o.sections {
		s := &o.sections[si]
		var relocs []pe.Reloc
		for _, r := range s.relocs {
			if !zeros[r.SymbolTableIndex] {
				relocs = append(relocs, r)
				continue
			}
			width := uint32(4)
			if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type == 1 || o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && r.Type == 14 {
				width = 8
			}
			if uint64(r.VirtualAddress)+uint64(width) > uint64(len(s.data)) {
				return fmt.Errorf("null weak relocation out of bounds")
			}
			absolute := o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && (r.Type == 1 || r.Type == 2) || o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && (r.Type == 1 || r.Type == 14)
			if absolute {
				continue
			} // The existing addend is already 0 + A.
			if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type == 4 && r.VirtualAddress > 0 {
				off := int(r.VirtualAddress)
				if binary.LittleEndian.Uint32(s.data[off:]) != 0 {
					return fmt.Errorf("nonzero null weak PC-relative addend")
				}
				if s.data[off-1] == 0xe8 || s.data[off-1] == 0xe9 {
					calls = append(calls, site{si, len(relocs)})
					relocs = append(relocs, r)
					continue
				}
				if off >= 3 && (s.data[off-3] == 0x48 || s.data[off-3] == 0x4c) && s.data[off-2] == 0x8d && s.data[off-1]&0xc7 == 5 {
					reg := (s.data[off-1] >> 3) & 7
					high := s.data[off-3]&4 != 0
					patch := []byte{0xb8 | reg, 0, 0, 0, 0, 0x90, 0x90}
					if high {
						patch = []byte{0x41, 0xb8 | reg, 0, 0, 0, 0, 0x90}
					}
					copy(s.data[off-3:off+4], patch)
					continue
				}
			}
			if o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && r.Type == 3 && binary.LittleEndian.Uint32(s.data[r.VirtualAddress:])&0x7fffffff == 0x14000000 {
				calls = append(calls, site{si, len(relocs)})
				relocs = append(relocs, r)
				continue
			}
			return fmt.Errorf("unsupported null weak relocation %#x", r.Type)
		}
		s.relocs = relocs
	}
	if len(calls) > 0 {
		code := []byte{0x48, 0xc7, 0xc0, 0, 0, 0, 0, 0xff, 0xe0}
		if o.machine == pe.IMAGE_FILE_MACHINE_ARM64 {
			code = []byte{0x10, 0, 0x80, 0xd2, 0, 0x02, 0x1f, 0xd6}
		}
		o.sections = append(o.sections, section{name: ".text", size: uint32(len(code)), data: code, flags: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE | 0x500000})
		index := uint32(len(o.symbols))
		o.addSymbol("bao_null_weak_call", int16(len(o.sections)), 0)
		o.symbols[index].StorageClass = 3
		o.symbols[index].Type = 0x20
		for _, site := range calls {
			o.sections[site.section].relocs[site.reloc].SymbolTableIndex = index
		}
	}
	for i := range zeros {
		o.symbols[i].SectionNumber = 0
		o.symbols[i].StorageClass = 2
	}
	return nil
}
