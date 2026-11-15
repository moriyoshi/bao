package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

// convertELF rewrites a little-endian ELF64 test object in another class
// and byte order: the header, the section headers and the structural
// sections; other contents keep their bytes and offsets. Relocation types
// keep their low byte for ELF32, which the editor never interprets.
func convertELF(t *testing.T, data []byte, to elfForm) []byte {
	t.Helper()
	shoff := le.Uint64(data[0x28:])
	shnum := int(le.Uint16(data[0x3c:]))
	out := bytes.Clone(data)
	clear(out[:64])
	copy(out, data[:16])
	if to.is32 {
		out[elf.EI_CLASS] = byte(elf.ELFCLASS32)
	}
	if to.bo == binary.ByteOrder(binary.BigEndian) {
		out[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	var headers []wideHeader
	for i := 0; i < shnum; i++ {
		h := shadowForm.readHeader(data[shoff+uint64(i)*sectionHeaderSize:])
		typ := elf.SectionType(h.typ)
		if i > 0 && structural(typ) {
			contents := bytes.Clone(data[h.offset : h.offset+h.size])
			if to.is32 && (typ == elf.SHT_REL || typ == elf.SHT_RELA) {
				n := int(shadowForm.relsize(typ == elf.SHT_RELA))
				for j := 0; j < len(contents); j += n {
					info := le.Uint64(contents[j+8:])
					le.PutUint64(contents[j+8:], info&^0xffffffff|info&0xff)
				}
			}
			converted, err := convertSection(shadowForm, to, typ, contents)
			if err != nil {
				t.Fatal(err)
			}
			for len(out)%8 != 0 {
				out = append(out, 0)
			}
			h.offset, h.size = uint64(len(out)), uint64(len(converted))
			switch typ {
			case elf.SHT_SYMTAB:
				h.entsize = uint64(to.symsize())
			case elf.SHT_REL, elf.SHT_RELA:
				h.entsize = uint64(to.relsize(typ == elf.SHT_RELA))
			}
			out = append(out, converted...)
		}
		headers = append(headers, h)
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	table := uint64(len(out))
	for _, h := range headers {
		out = to.appendHeader(out, h)
	}
	bo := to.bo
	bo.PutUint16(out[16:], uint16(elf.ET_REL))
	bo.PutUint16(out[18:], le.Uint16(data[18:]))
	bo.PutUint32(out[20:], 1)
	if to.is32 {
		bo.PutUint32(out[32:], uint32(table))
		bo.PutUint16(out[40:], 52)
		bo.PutUint16(out[46:], 40)
		bo.PutUint16(out[48:], uint16(shnum))
		bo.PutUint16(out[50:], le.Uint16(data[0x3e:]))
	} else {
		bo.PutUint64(out[40:], table)
		bo.PutUint16(out[52:], 64)
		bo.PutUint16(out[58:], 64)
		bo.PutUint16(out[60:], uint16(shnum))
		bo.PutUint16(out[62:], le.Uint16(data[0x3e:]))
	}
	return out
}

// elfRelocations lists every REL and RELA entry by target section, offset,
// type (low byte), symbol name and addend, in any class and byte order.
func elfRelocations(t *testing.T, data []byte) []string {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	syms, _ := f.Symbols()
	name := func(i uint64) string {
		if i == 0 || int(i) > len(syms) {
			return "-"
		}
		return syms[i-1].Name
	}
	var out []string
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA && s.Type != elf.SHT_REL {
			continue
		}
		b, _ := s.Data()
		rela := s.Type == elf.SHT_RELA
		n := map[bool]map[bool]int{true: {true: 12, false: 8}, false: {true: 24, false: 16}}[f.Class == elf.ELFCLASS32][rela]
		for i := 0; i+n <= len(b); i += n {
			var off, sym, typ uint64
			var add int64
			if f.Class == elf.ELFCLASS32 {
				info := f.ByteOrder.Uint32(b[i+4:])
				off, sym, typ = uint64(f.ByteOrder.Uint32(b[i:])), uint64(info>>8), uint64(info&0xff)
				if rela {
					add = int64(int32(f.ByteOrder.Uint32(b[i+8:])))
				}
			} else {
				info := f.ByteOrder.Uint64(b[i+8:])
				off, sym, typ = f.ByteOrder.Uint64(b[i:]), info>>32, info&0xff
				if rela {
					add = int64(f.ByteOrder.Uint64(b[i+16:]))
				}
			}
			out = append(out, fmt.Sprintf("%s+%d %d %s%+d", f.Sections[s.Info].Name, off, typ, name(sym), add))
		}
	}
	return out
}

var wideForms = map[string]elfForm{
	"ELF32 little-endian": {is32: true, bo: binary.LittleEndian},
	"ELF32 big-endian":    {is32: true, bo: binary.BigEndian},
	"ELF64 big-endian":    {bo: binary.BigEndian},
}

func TestWideELFEditsMatchELF64(t *testing.T) {
	cases := map[string]Edits{
		"wrap and rename":  {Wrap: []string{"foo", "bar"}, Rename: map[string]string{"helper": "helper_renamed"}},
		"localize, strip":  {Visibility: Visibility{Localize: matcher(t, false, "foo"), StripUnneeded: true}},
		"keep-global":      {Visibility: Visibility{KeepGlobal: matcher(t, false, "bar")}},
		"remove a section": {RemoveSection: matcher(t, false, ".debug_info")},
		"add symbols":      {AddSymbols: addSymbols(t, "alias=@foo:4,function", "marker=.text:8,local", "abs=0x40,weak")},
	}
	for formName, form := range wideForms {
		for name, e := range cases {
			for _, in := range [][]byte{fixture(), sectionFixture()} {
				want, wn, err := Edit(in, e)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				got, gn, err := Edit(convertELF(t, in, form), e)
				if err != nil || gn != wn {
					t.Fatalf("%s %s: %d edits, %v; want %d", formName, name, gn, err, wn)
				}
				ws, wr, wg, wsyms := layout(t, want)
				gs, gr, gg, gsyms := layout(t, got)
				if !reflect.DeepEqual(gs, ws) || !reflect.DeepEqual(gr, wr) || !reflect.DeepEqual(gg, wg) || !reflect.DeepEqual(gsyms, wsyms) {
					t.Errorf("%s %s: layout differs:\n%q %v %q %q\n%q %v %q %q", formName, name, gs, gr, gg, gsyms, ws, wr, wg, wsyms)
				}
				wantRel := elfRelocations(t, convertELF(t, want, form))
				if gotRel := elfRelocations(t, got); !reflect.DeepEqual(gotRel, wantRel) {
					t.Errorf("%s %s: relocations %q, want %q", formName, name, gotRel, wantRel)
				}
				// The edited object keeps its class and byte order.
				f, err := elf.NewFile(bytes.NewReader(got))
				if err != nil || (f.Class == elf.ELFCLASS32) != form.is32 || (f.ByteOrder == binary.ByteOrder(binary.BigEndian)) != (form.bo == binary.ByteOrder(binary.BigEndian)) {
					t.Fatalf("%s %s: result %v %v, %v", formName, name, f.Class, f.ByteOrder, err)
				}
			}
		}
	}
}

// Bytes the edit does not touch keep their offsets, and unchanged objects
// come back as they are.
func TestWideELFPreservesBytes(t *testing.T) {
	for formName, form := range wideForms {
		in := convertELF(t, sectionFixture(), form)
		out, n, err := Edit(in, Edits{Rename: map[string]string{"nosuch": "x"}})
		if err != nil || n != 0 || !bytes.Equal(out, in) {
			t.Fatalf("%s: unchanged edit: %d, %v", formName, n, err)
		}
		out, _, err = Edit(in, Edits{Rename: map[string]string{"foo": "foo2"}})
		if err != nil {
			t.Fatal(err)
		}
		f, _ := elf.NewFile(bytes.NewReader(in))
		for _, s := range f.Sections {
			if s.Type == elf.SHT_PROGBITS && s.Size > 0 {
				if !bytes.Equal(out[s.Offset:s.Offset+s.Size], in[s.Offset:s.Offset+s.Size]) {
					t.Errorf("%s: %s moved or changed", formName, s.Name)
				}
			}
		}
	}
	mips := convertELF(t, fixture(), elfForm{bo: binary.BigEndian})
	binary.BigEndian.PutUint16(mips[18:], uint16(elf.EM_MIPS))
	if _, _, err := Edit(mips, Edits{Rename: map[string]string{"foo": "x"}}); err == nil {
		t.Error("MIPS64 accepted")
	}
}
