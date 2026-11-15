package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

// ELF32 and big-endian ELF objects are edited through a shadow: an
// equivalent little-endian ELF64 file that the ELF editor handles. The
// shadow is a 64-byte header followed by the whole input, so every input
// offset maps to the shadow by a constant, plus converted copies of the
// sections the editor reads: the symbol table, REL and RELA sections,
// section groups, extended section indices and the section header table.
// The edited shadow is converted back into the input's class and byte
// order: the input's bytes keep their offsets, and the sections the editor
// rewrote are appended, converted where they are structural.

const shadowShift = 64

// elfOrder reads and appends in one byte order.
type elfOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

type elfForm struct {
	is32    bool
	bo      elfOrder
	machine elf.Machine
}

func (w elfForm) ehsize() int  { return map[bool]int{false: 64, true: 52}[w.is32] }
func (w elfForm) shsize() int  { return map[bool]int{false: 64, true: 40}[w.is32] }
func (w elfForm) symsize() int { return map[bool]int{false: 24, true: 16}[w.is32] }
func (w elfForm) align() int   { return map[bool]int{false: 8, true: 4}[w.is32] }

// relsize returns an entry's size for REL or RELA.
func (w elfForm) relsize(rela bool) int {
	switch {
	case w.is32 && rela:
		return 12
	case w.is32:
		return 8
	case rela:
		return 24
	}
	return 16
}

// wideELF reports an ELF relocatable object that is 32-bit or big-endian.
func wideELF(data []byte) (elfForm, bool) {
	if len(data) < 52 || !bytes.HasPrefix(data, []byte(elf.ELFMAG)) {
		return elfForm{}, false
	}
	w := elfForm{is32: elf.Class(data[elf.EI_CLASS]) == elf.ELFCLASS32, bo: binary.LittleEndian}
	big := elf.Data(data[elf.EI_DATA]) == elf.ELFDATA2MSB
	if big {
		w.bo = binary.BigEndian
	}
	w.machine = elf.Machine(w.bo.Uint16(data[18:]))
	return w, w.is32 || big
}

type wideHeader struct {
	name, typ                 uint32
	flags, addr, offset, size uint64
	link, info                uint32
	addralign, entsize        uint64
}

func (w elfForm) readHeader(h []byte) wideHeader {
	bo := w.bo
	if w.is32 {
		return wideHeader{bo.Uint32(h), bo.Uint32(h[4:]), uint64(bo.Uint32(h[8:])), uint64(bo.Uint32(h[12:])), uint64(bo.Uint32(h[16:])), uint64(bo.Uint32(h[20:])), bo.Uint32(h[24:]), bo.Uint32(h[28:]), uint64(bo.Uint32(h[32:])), uint64(bo.Uint32(h[36:]))}
	}
	return wideHeader{bo.Uint32(h), bo.Uint32(h[4:]), bo.Uint64(h[8:]), bo.Uint64(h[16:]), bo.Uint64(h[24:]), bo.Uint64(h[32:]), bo.Uint32(h[40:]), bo.Uint32(h[44:]), bo.Uint64(h[48:]), bo.Uint64(h[56:])}
}

func (w elfForm) appendHeader(out []byte, h wideHeader) []byte {
	bo := w.bo
	if w.is32 {
		for _, v := range []uint32{h.name, h.typ, uint32(h.flags), uint32(h.addr), uint32(h.offset), uint32(h.size), h.link, h.info, uint32(h.addralign), uint32(h.entsize)} {
			out = bo.AppendUint32(out, v)
		}
		return out
	}
	out = bo.AppendUint32(bo.AppendUint32(out, h.name), h.typ)
	for _, v := range []uint64{h.flags, h.addr, h.offset, h.size} {
		out = bo.AppendUint64(out, v)
	}
	out = bo.AppendUint32(bo.AppendUint32(out, h.link), h.info)
	return bo.AppendUint64(bo.AppendUint64(out, h.addralign), h.entsize)
}

var shadowForm = elfForm{bo: binary.LittleEndian}

// convert rewrites a structural section's contents from one form to
// another. Other sections are returned as they are.
func convertSection(from, to elfForm, typ elf.SectionType, data []byte) ([]byte, error) {
	switch typ {
	case elf.SHT_SYMTAB:
		n, size := from.symsize(), to.symsize()
		if len(data)%n != 0 {
			return nil, errors.New("malformed ELF symbol table")
		}
		out := make([]byte, 0, len(data)/n*size)
		for i := 0; i < len(data); i += n {
			e := data[i:]
			var name uint32
			var info, other byte
			var shndx uint16
			var value, sz uint64
			if from.is32 {
				name, value, sz, info, other, shndx = from.bo.Uint32(e), uint64(from.bo.Uint32(e[4:])), uint64(from.bo.Uint32(e[8:])), e[12], e[13], from.bo.Uint16(e[14:])
			} else {
				name, info, other, shndx, value, sz = from.bo.Uint32(e), e[4], e[5], from.bo.Uint16(e[6:]), from.bo.Uint64(e[8:]), from.bo.Uint64(e[16:])
			}
			if to.is32 {
				if value > 0xffffffff || sz > 0xffffffff {
					return nil, errors.New("ELF symbol value does not fit 32 bits")
				}
				out = to.bo.AppendUint32(to.bo.AppendUint32(to.bo.AppendUint32(out, name), uint32(value)), uint32(sz))
				out = to.bo.AppendUint16(append(out, info, other), shndx)
			} else {
				out = to.bo.AppendUint16(append(to.bo.AppendUint32(out, name), info, other), shndx)
				out = to.bo.AppendUint64(to.bo.AppendUint64(out, value), sz)
			}
		}
		return out, nil
	case elf.SHT_REL, elf.SHT_RELA:
		rela := typ == elf.SHT_RELA
		n := from.relsize(rela)
		if len(data)%n != 0 {
			return nil, errors.New("malformed ELF relocation section")
		}
		var out []byte
		for i := 0; i < len(data); i += n {
			e := data[i:]
			var off uint64
			var sym, rtype uint32
			var add int64
			if from.is32 {
				info := from.bo.Uint32(e[4:])
				off, sym, rtype = uint64(from.bo.Uint32(e)), info>>8, info&0xff
				if rela {
					add = int64(int32(from.bo.Uint32(e[8:])))
				}
			} else {
				info := from.bo.Uint64(e[8:])
				off, sym, rtype = from.bo.Uint64(e), uint32(info>>32), uint32(info)
				if rela {
					add = int64(from.bo.Uint64(e[16:]))
				}
			}
			if to.is32 {
				if sym >= 1<<24 || rtype > 0xff || off > 0xffffffff || add != int64(int32(add)) {
					return nil, errors.New("ELF relocation does not fit ELF32")
				}
				out = to.bo.AppendUint32(to.bo.AppendUint32(out, uint32(off)), sym<<8|rtype)
				if rela {
					out = to.bo.AppendUint32(out, uint32(int32(add)))
				}
			} else {
				out = to.bo.AppendUint64(to.bo.AppendUint64(out, off), uint64(sym)<<32|uint64(rtype))
				if rela {
					out = to.bo.AppendUint64(out, uint64(add))
				}
			}
		}
		return out, nil
	case elf.SHT_GROUP, elf.SHT_SYMTAB_SHNDX:
		if len(data)%4 != 0 {
			return nil, errors.New("malformed ELF word table")
		}
		out := make([]byte, 0, len(data))
		for i := 0; i < len(data); i += 4 {
			out = to.bo.AppendUint32(out, from.bo.Uint32(data[i:]))
		}
		return out, nil
	}
	return data, nil
}

func structural(typ elf.SectionType) bool {
	return typ == elf.SHT_SYMTAB || typ == elf.SHT_REL || typ == elf.SHT_RELA || typ == elf.SHT_GROUP || typ == elf.SHT_SYMTAB_SHNDX
}

// toShadow builds the little-endian ELF64 shadow of a wide object.
func toShadow(data []byte, w elfForm) ([]byte, error) {
	bo := w.bo
	if elf.Type(bo.Uint16(data[16:])) != elf.ET_REL {
		return nil, errors.New("not an ELF relocatable object")
	}
	if w.machine == elf.EM_MIPS && !w.is32 {
		return nil, errors.New("MIPS64 relocations pack several types into r_info and are unsupported")
	}
	var shoff uint64
	var shentsize, shnum, shstrndx int
	if w.is32 {
		shoff, shentsize, shnum, shstrndx = uint64(bo.Uint32(data[32:])), int(bo.Uint16(data[46:])), int(bo.Uint16(data[48:])), int(bo.Uint16(data[50:]))
	} else {
		if len(data) < 64 {
			return nil, errors.New("short ELF header")
		}
		shoff, shentsize, shnum, shstrndx = bo.Uint64(data[40:]), int(bo.Uint16(data[58:])), int(bo.Uint16(data[60:])), int(bo.Uint16(data[62:]))
	}
	if shoff == 0 {
		return nil, errors.New("ELF object has no section headers")
	}
	if shentsize != w.shsize() || shoff > uint64(len(data)) || uint64(len(data))-shoff < uint64(w.shsize()) {
		return nil, errors.New("ELF section headers are out of range")
	}
	if shnum == 0 {
		shnum = int(w.readHeader(data[shoff:]).size)
	}
	if uint64(shnum) > (uint64(len(data))-shoff)/uint64(w.shsize()) {
		return nil, errors.New("ELF section headers are out of range")
	}
	out := make([]byte, shadowShift)
	copy(out, data[:16])
	out[elf.EI_CLASS], out[elf.EI_DATA] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB)
	le.PutUint16(out[16:], uint16(elf.ET_REL))
	le.PutUint16(out[18:], uint16(w.machine))
	le.PutUint32(out[20:], 1)
	le.PutUint32(out[48:], bo.Uint32(data[map[bool]int{false: 48, true: 36}[w.is32]:]))
	le.PutUint16(out[52:], 64)
	le.PutUint16(out[58:], sectionHeaderSize)
	le.PutUint16(out[60:], uint16(min(shnum, int(elf.SHN_LORESERVE))))
	le.PutUint16(out[62:], uint16(shstrndx))
	out = append(out, data...)
	headers := make([]wideHeader, shnum)
	for i := range headers {
		h := w.readHeader(data[shoff+uint64(i)*uint64(w.shsize()):])
		typ := elf.SectionType(h.typ)
		if i > 0 && typ != elf.SHT_NOBITS && (h.offset > uint64(len(data)) || h.size > uint64(len(data))-h.offset) {
			return nil, fmt.Errorf("ELF section %d is out of range", i)
		}
		if typ == shtCREL && w.is32 {
			return nil, errors.New("CREL relocations in ELF32 objects are unsupported")
		}
		if i > 0 && h.offset != 0 {
			h.offset += shadowShift
		}
		if i > 0 && structural(typ) {
			contents, err := convertSection(w, shadowForm, typ, data[h.offset-shadowShift:h.offset-shadowShift+h.size])
			if err != nil {
				return nil, fmt.Errorf("ELF section %d: %w", i, err)
			}
			for len(out)%8 != 0 {
				out = append(out, 0)
			}
			h.offset, h.size = uint64(len(out)), uint64(len(contents))
			switch typ {
			case elf.SHT_SYMTAB:
				h.entsize = symbolSize
			case elf.SHT_REL:
				h.entsize = 16
			case elf.SHT_RELA:
				h.entsize = 24
			}
			out = append(out, contents...)
		}
		headers[i] = h
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	le.PutUint64(out[40:], uint64(len(out)))
	for _, h := range headers {
		out = shadowForm.appendHeader(out, h)
	}
	return out, nil
}

// fromShadow converts an edited shadow back into the input's form. input
// is the original object, which the shadow embeds at shadowShift.
func fromShadow(input, shadow []byte, w elfForm) ([]byte, error) {
	f, err := parseELF(shadow)
	if err != nil {
		return nil, err
	}
	original := uint64(shadowShift + len(input))
	head := w.ehsize()
	out := append([]byte{}, input[:head]...)
	out = append(out, shadow[shadowShift+head:original]...)
	shnum := len(f.sections)
	headers := make([]wideHeader, shnum)
	for i := range headers {
		h := shadowForm.readHeader(shadow[f.shoff+uint64(i)*sectionHeaderSize:])
		typ := elf.SectionType(h.typ)
		switch {
		case i == 0 || h.offset == 0:
		case typ == elf.SHT_NOBITS || h.offset >= shadowShift+uint64(head) && h.offset+h.size <= original && !structural(typ):
			h.offset -= shadowShift
		default:
			// The editor wrote it, or it is structural: append it in the
			// input's form.
			contents := shadow[h.offset : h.offset+h.size]
			if structural(typ) {
				if contents, err = convertSection(shadowForm, w, typ, contents); err != nil {
					return nil, fmt.Errorf("ELF section %d: %w", i, err)
				}
				switch typ {
				case elf.SHT_SYMTAB:
					h.entsize = uint64(w.symsize())
				case elf.SHT_REL, elf.SHT_RELA:
					h.entsize = uint64(w.relsize(typ == elf.SHT_RELA))
				}
			}
			for len(out)%w.align() != 0 {
				out = append(out, 0)
			}
			h.offset, h.size = uint64(len(out)), uint64(len(contents))
			out = append(out, contents...)
		}
		headers[i] = h
	}
	for len(out)%w.align() != 0 {
		out = append(out, 0)
	}
	shoff := uint64(len(out))
	if w.is32 && shoff > 0xffffffff {
		return nil, errors.New("ELF32 object is too large")
	}
	for _, h := range headers {
		out = w.appendHeader(out, h)
	}
	shnumField, shstrndx := le.Uint16(shadow[60:]), le.Uint16(shadow[62:])
	if w.is32 {
		w.bo.PutUint32(out[32:], uint32(shoff))
		w.bo.PutUint16(out[48:], shnumField)
		w.bo.PutUint16(out[50:], shstrndx)
	} else {
		w.bo.PutUint64(out[40:], shoff)
		w.bo.PutUint16(out[60:], shnumField)
		w.bo.PutUint16(out[62:], shstrndx)
	}
	return out, nil
}

// editWideELF edits a 32-bit or big-endian ELF object through its shadow.
func editWideELF(data []byte, w elfForm, e Edits) (objectResult, error) {
	shadow, err := toShadow(data, w)
	if err != nil {
		return objectResult{}, err
	}
	r, err := editELF(shadow, e)
	if err != nil || r.edited == 0 {
		r.data = data
		return r, err
	}
	if r.data, err = fromShadow(data, r.data, w); err != nil {
		return objectResult{}, err
	}
	return r, nil
}

// parseWideELF parses a 32-bit or big-endian ELF object for its names.
func parseWideELF(data []byte, w elfForm) (*elfFile, error) {
	shadow, err := toShadow(data, w)
	if err != nil {
		return nil, err
	}
	return parseELF(shadow)
}
