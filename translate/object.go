package translate

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strings"
)

// objectImage is a relocatable image, not an executable loader. Rebuilding the
// file preserves section virtual addresses and every native instruction. File
// data is laid out at those relative addresses because loadmacho indexes its
// segment buffer by section address rather than section file offset.
type objectImage struct {
	flags    uint32
	cpu      macho.Cpu
	subCPU   uint32
	sections []imageSection
	symbols  []macho.Symbol
	versions [][]byte
}

type imageSection struct {
	name, seg                       string
	addr, size                      uint64
	align, flags                    uint32
	reserved1, reserved2, reserved3 uint32
	data                            []byte
	relocs                          []macho.Reloc
}

func readImage(o Object) (*objectImage, error) {
	f, err := openObject(o)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Symtab == nil {
		return nil, fmt.Errorf("object has no symbol table")
	}
	m := &objectImage{flags: f.Flags, cpu: f.Cpu, subCPU: f.SubCpu, symbols: append([]macho.Symbol(nil), f.Symtab.Syms...)}
	// debug/macho normalizes some Go-looking names and does not populate its
	// SymtabCmd. Read the raw command so a round trip preserves ALL names.
	cmd := f.Symtab.Raw()
	if len(cmd) < 24 {
		return nil, fmt.Errorf("short symbol-table command")
	}
	symoff := uint64(binary.LittleEndian.Uint32(cmd[8:]))
	stroff := uint64(binary.LittleEndian.Uint32(cmd[16:]))
	strsize := uint64(binary.LittleEndian.Uint32(cmd[20:]))
	if symoff+16*uint64(len(m.symbols)) > uint64(len(o.Data)) || stroff+strsize > uint64(len(o.Data)) {
		return nil, fmt.Errorf("symbol table outside object")
	}
	for i := range m.symbols {
		nameoff := uint64(binary.LittleEndian.Uint32(o.Data[symoff+16*uint64(i):]))
		if nameoff >= strsize {
			return nil, fmt.Errorf("symbol name outside string table")
		}
		name := o.Data[stroff+nameoff : stroff+strsize]
		end := bytes.IndexByte(name, 0)
		if end < 0 {
			return nil, fmt.Errorf("unterminated symbol name")
		}
		m.symbols[i].Name = string(name[:end])
	}
	var reserved [][3]uint32
	var dataInCode []byte
	for _, l := range f.Loads {
		raw := l.Raw()
		switch binary.LittleEndian.Uint32(raw) {
		case 25:
			for at := 72; at+80 <= len(raw); at += 80 {
				reserved = append(reserved, [3]uint32{
					binary.LittleEndian.Uint32(raw[at+68:]),
					binary.LittleEndian.Uint32(raw[at+72:]),
					binary.LittleEndian.Uint32(raw[at+76:]),
				})
			}
		case 0x24, 0x32:
			m.versions = append(m.versions, bytes.Clone(raw))
		case 2, 11, 0x2e: // Rebuilt symbol table; no indirect symbol sections allowed below. LOH is optional.
		case 0x29:
			if len(raw) < 16 {
				return nil, fmt.Errorf("short LC_DATA_IN_CODE")
			}
			length := uint64(binary.LittleEndian.Uint32(raw[12:]))
			if length != 0 && f.Cpu == macho.CpuAmd64 {
				offset := uint64(binary.LittleEndian.Uint32(raw[8:]))
				if length%8 != 0 || offset+length > uint64(len(o.Data)) {
					return nil, fmt.Errorf("invalid amd64 data-in-code payload")
				}
				dataInCode = bytes.Clone(o.Data[offset : offset+length])
			} else if length != 0 {
				return nil, fmt.Errorf("cannot rebuild nonempty LC_DATA_IN_CODE")
			}
		default:
			return nil, fmt.Errorf("cannot rebuild load command %#x", binary.LittleEndian.Uint32(raw))
		}
	}
	if len(reserved) != len(f.Sections) {
		return nil, fmt.Errorf("requires one segment with all sections")
	}
	for i, s := range f.Sections {
		if s.Align > 20 || s.Addr+s.Size < s.Addr || s.Addr+s.Size > 512<<20 {
			return nil, fmt.Errorf("section exceeds experimental image size/alignment bounds")
		}
		if t := s.Flags & 0xff; t == 6 || t == 7 || t == 8 || t == 0x10 {
			return nil, fmt.Errorf("indirect/stub section %s/%s requires additional symbol-table handling", s.Seg, s.Name)
		}
		if s.Size != 0 {
			if strings.HasPrefix(s.Name, "__objc") || strings.HasPrefix(s.Name, "__swift") {
				return nil, fmt.Errorf("native Objective-C/Swift image metadata requires additional registration support")
			}
			if s.Seg != "__TEXT" && s.Seg != "__DATA" && s.Seg != "__DWARF" && s.Seg != "__LLVM" && !(s.Seg == "__LD" && s.Name == "__compact_unwind") {
				return nil, fmt.Errorf("unsupported native segment/section %s/%s", s.Seg, s.Name)
			}
			switch s.Flags & 0xff {
			case 0, 1, 2, 3, 4, 9, 10, 14, 17, 18, 19, 20, 21:
			case 11:
				if s.Name != "__eh_frame" && s.Name != "__bao_eh_frame" {
					return nil, fmt.Errorf("unresolved coalesced native section %s", s.Name)
				}
			default:
				return nil, fmt.Errorf("unsupported native section type %#x", s.Flags&0xff)
			}
		}
		is := imageSection{name: s.Name, seg: s.Seg, addr: s.Addr, size: s.Size, align: s.Align, flags: s.Flags,
			reserved1: reserved[i][0], reserved2: reserved[i][1], reserved3: reserved[i][2],
			relocs: append([]macho.Reloc(nil), s.Relocs...)}
		if s.Flags&0xff != 1 && s.Flags&0xff != 0x12 {
			if uint64(s.Offset)+s.Size > uint64(len(o.Data)) {
				return nil, fmt.Errorf("section data outside object")
			}
			is.data = bytes.Clone(o.Data[uint64(s.Offset) : uint64(s.Offset)+s.Size])
		}
		m.sections = append(m.sections, is)
	}
	if len(dataInCode) != 0 {
		// Intel jump tables remain byte-for-byte in executable __text. Keep the
		// producer's annotations in the artifact as provenance; Go does not use
		// LC_DATA_IN_CODE for code placement or native execution.
		for at := 0; at < len(dataInCode); at += 8 {
			offset := uint64(binary.LittleEndian.Uint32(dataInCode[at:]))
			length := uint64(binary.LittleEndian.Uint16(dataInCode[at+4:]))
			kind := binary.LittleEndian.Uint16(dataInCode[at+6:])
			valid := false
			for _, s := range f.Sections {
				valid = valid || s.Seg == "__TEXT" && s.Flags&0x80000400 != 0 && offset >= uint64(s.Offset) && offset+length <= uint64(s.Offset)+s.Size
			}
			if !valid || length == 0 || kind < 1 || kind > 5 {
				return nil, fmt.Errorf("unsupported amd64 data-in-code entry")
			}
		}
		addr := (m.end() + 7) &^ 7
		m.sections = append(m.sections, imageSection{name: "__bao_dice", seg: "__TEXT", addr: addr, size: uint64(len(dataInCode)), align: 3, data: dataInCode})
	}
	for _, s := range m.symbols {
		if s.Type&0xe0 != 0 {
			continue
		}
		switch s.Type & 0xe {
		case 0:
			if s.Sect != 0 || s.Value != 0 {
				return nil, fmt.Errorf("tentative/common native symbol %q requires allocation support", s.Name)
			}
		case 0xe:
			if s.Sect == 0 || int(s.Sect) > len(m.sections) {
				return nil, fmt.Errorf("native symbol %q has invalid section", s.Name)
			}
			t := m.sections[s.Sect-1]
			if s.Value < t.addr || s.Value > t.addr+t.size {
				return nil, fmt.Errorf("native symbol %q is outside its section", s.Name)
			}
		default:
			return nil, fmt.Errorf("unsupported absolute/indirect native symbol %q", s.Name)
		}
	}
	return m, nil
}

func (m *objectImage) end() uint64 {
	var end uint64
	for _, s := range m.sections {
		end = max(end, s.addr+s.size)
	}
	return end
}

func fixedName(s string) [16]byte {
	var name [16]byte
	copy(name[:], s)
	return name
}

func (m *objectImage) encode() ([]byte, error) {
	if len(m.sections) > 255 || m.end() > 512<<20 {
		return nil, fmt.Errorf("image exceeds experimental bounds")
	}
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	cmdsize := 72 + 80*len(m.sections) + 24
	for _, c := range m.versions {
		cmdsize += len(c)
	}
	start := uint64(32 + cmdsize)
	end := m.end()
	reloff := start + end
	relocSize := uint64(0)
	for _, s := range m.sections {
		relocSize += uint64(len(s.relocs)) * 8
	}
	symoff := reloff + relocSize
	stroff := symoff + 16*uint64(len(m.symbols))
	strtab := []byte{0}
	nameoffs := make([]uint32, len(m.symbols))
	for i, s := range m.symbols {
		nameoffs[i] = uint32(len(strtab))
		strtab = append(strtab, s.Name...)
		strtab = append(strtab, 0)
	}
	cpu := m.cpu
	if cpu == 0 {
		cpu = macho.CpuArm64
	}
	w([8]uint32{macho.Magic64, uint32(cpu), m.subCPU, uint32(macho.TypeObj), uint32(2 + len(m.versions)), uint32(cmdsize), m.flags, 0})
	w([2]uint32{25, uint32(72 + 80*len(m.sections))})
	w([16]byte{})
	w([4]uint64{0, end, start, end})
	w([4]uint32{7, 7, uint32(len(m.sections)), 0})
	for _, s := range m.sections {
		if len(s.name) > 16 || len(s.seg) > 16 || (s.data != nil && uint64(len(s.data)) != s.size) {
			return nil, fmt.Errorf("invalid section name/data size")
		}
		w(fixedName(s.name))
		w(fixedName(s.seg))
		w([2]uint64{s.addr, s.size})
		offset := start + s.addr
		if s.flags&0xff == 1 || s.flags&0xff == 0x12 {
			offset = 0
		}
		w([8]uint32{uint32(offset), s.align, uint32(reloff), uint32(len(s.relocs)), s.flags, s.reserved1, s.reserved2, s.reserved3})
		reloff += uint64(len(s.relocs)) * 8
	}
	w([6]uint32{2, 24, uint32(symoff), uint32(len(m.symbols)), uint32(stroff), uint32(len(strtab))})
	for _, c := range m.versions {
		b.Write(c)
	}
	image := make([]byte, end)
	for _, s := range m.sections {
		copy(image[s.addr:s.addr+s.size], s.data)
	}
	b.Write(image)
	for _, s := range m.sections {
		for _, r := range s.relocs {
			if r.Scattered {
				return nil, fmt.Errorf("scattered relocation is unsupported")
			}
			v := r.Value | uint32(r.Len)<<25 | uint32(r.Type)<<28
			if r.Pcrel {
				v |= 1 << 24
			}
			if r.Extern {
				v |= 1 << 27
			}
			w([2]uint32{r.Addr, v})
		}
	}
	for i, s := range m.symbols {
		w(nameoffs[i])
		w(s.Type)
		w(s.Sect)
		w(s.Desc)
		w(s.Value)
	}
	b.Write(strtab)
	return b.Bytes(), nil
}
