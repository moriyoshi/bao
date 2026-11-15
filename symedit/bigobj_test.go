package symedit

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

// toBigObj rewrites a regular COFF object in the bigobj format: a 56-byte
// header, then the same section headers and contents moved down, and a
// symbol table of 20-byte records at the end, with the same record indices.
func toBigObj(t *testing.T, data []byte) []byte {
	t.Helper()
	le := binary.LittleEndian
	nsect := int(le.Uint16(data[2:]))
	symoff, records := le.Uint32(data[8:]), int(le.Uint32(data[12:]))
	delta := uint32(coffBigHeader - coffFileHeader)
	out := make([]byte, coffBigHeader)
	le.PutUint16(out[2:], 0xffff)
	le.PutUint16(out[4:], 2)
	copy(out[6:], data[:2])
	copy(out[12:], bigObjClassID)
	le.PutUint32(out[44:], uint32(nsect))
	out = append(out, data[coffFileHeader:symoff]...)
	for i := 0; i < nsect; i++ {
		h := out[coffBigHeader+i*coffSectionHeader:]
		for _, at := range []int{20, 24} {
			if v := le.Uint32(h[at:]); v != 0 {
				le.PutUint32(h[at:], v+delta)
			}
		}
	}
	le.PutUint32(out[48:], uint32(len(out)))
	le.PutUint32(out[52:], uint32(records))
	for i := 0; i < records; {
		e := data[int(symoff)+i*coffSymbolSize:]
		big := make([]byte, coffBigSymbolSize)
		copy(big, e[:12])
		le.PutUint32(big[12:], uint32(int32(int16(le.Uint16(e[12:])))))
		copy(big[16:], e[14:18])
		out = append(out, big...)
		for j := 1; j <= int(e[17]); j++ {
			aux := make([]byte, coffBigSymbolSize)
			copy(aux, data[int(symoff)+(i+j)*coffSymbolSize:][:coffSymbolSize])
			out = append(out, aux...)
		}
		i += 1 + int(e[17])
	}
	return append(out, data[int(symoff)+records*coffSymbolSize:]...)
}

// fromBigObj is toBigObj's inverse, for reading results with debug/pe.
// Section numbers must fit the regular format.
func fromBigObj(t *testing.T, data []byte) []byte {
	t.Helper()
	le := binary.LittleEndian
	if !isBigObj(data) {
		t.Fatal("not a bigobj object")
	}
	nsect := int(le.Uint32(data[44:]))
	symoff, records := le.Uint32(data[48:]), int(le.Uint32(data[52:]))
	delta := uint32(coffBigHeader - coffFileHeader)
	out := make([]byte, coffFileHeader)
	copy(out, data[6:8])
	le.PutUint16(out[2:], uint16(nsect))
	// Everything between the headers and the symbol table, which edits
	// may also have appended after it, keeps its relative position.
	body := append([]byte{}, data[coffBigHeader:symoff]...)
	out = append(out, body...)
	for i := 0; i < nsect; i++ {
		h := out[coffFileHeader+i*coffSectionHeader:]
		for _, at := range []int{20, 24} {
			if v := le.Uint32(h[at:]); v != 0 {
				le.PutUint32(h[at:], v-delta)
			}
		}
	}
	le.PutUint32(out[8:], uint32(len(out)))
	le.PutUint32(out[12:], uint32(records))
	for i := 0; i < records; {
		e := data[int(symoff)+i*coffBigSymbolSize:]
		section := int32(le.Uint32(e[12:]))
		if section > 0x7fff {
			t.Fatalf("section number %d does not fit a regular object", section)
		}
		reg := make([]byte, coffSymbolSize)
		copy(reg, e[:12])
		le.PutUint16(reg[12:], uint16(section))
		copy(reg[14:], e[16:20])
		out = append(out, reg...)
		for j := 1; j <= int(e[19]); j++ {
			aux := data[int(symoff)+(i+j)*coffBigSymbolSize:]
			if le.Uint16(aux[16:]) != 0 {
				t.Fatal("associative section number does not fit a regular object")
			}
			out = append(out, aux[:coffSymbolSize]...)
		}
		i += 1 + int(e[19])
	}
	return append(out, data[int(symoff)+records*coffBigSymbolSize:]...)
}

func TestBigObjConverters(t *testing.T) {
	in := coffFixture("")
	if back := fromBigObj(t, toBigObj(t, in)); !bytes.Equal(back, in) {
		t.Fatal("bigobj round trip changed the object")
	}
	f, err := parseCOFF(toBigObj(t, in))
	if err != nil || !f.big || f.symSize != coffBigSymbolSize {
		t.Fatalf("parseCOFF = %+v, %v", f, err)
	}
}

// Every COFF edit gives the same result on a bigobj copy of the input.
func TestBigObjEditsMatchRegular(t *testing.T) {
	drectve := "/EXPORT:PyList_New -exclude-symbols:XML_Parse "
	for name, e := range map[string]Edits{
		"wrap and rename": {Wrap: []string{"PyList_New", "malloc"}, Rename: map[string]string{"XML_Parse": "ext_XML_Parse_long_name", "helper": "helper2"}},
		"bindings":        {Visibility: Visibility{KeepGlobal: matcher(t, true, "Py*"), StripUnneeded: true}},
		"weaken":          {Visibility: Visibility{Weaken: matcher(t, false, "PyList_New", "absent")}},
		"remove sections": {RemoveSection: matcher(t, true, ".debug$*", ".text$c")},
		"only sections":   {OnlySection: matcher(t, false, ".text", ".pdata")},
		"add symbols":     {AddSymbols: addSymbols(t, "alias=.text:4,function", "key_alias=@comdat_key:2", "abs=0x40,local")},
	} {
		in := coffFixture(drectve)
		regular, n, err := Edit(in, e)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		big, bn, err := Edit(toBigObj(t, in), e)
		if err != nil || bn != n {
			t.Fatalf("%s: bigobj: %d edits, %v; want %d", name, bn, err, n)
		}
		if !isBigObj(big) {
			t.Fatalf("%s: result is not bigobj", name)
		}
		back := fromBigObj(t, big)
		if got, want := readCOFF(t, back), readCOFF(t, regular); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: symbols, relocations or tags differ:\n%+v\n%+v", name, got, want)
		}
		if got, want := readCOFFLayout(t, back), readCOFFLayout(t, regular); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: layout differs:\n%+v\n%+v", name, got, want)
		}
		if got, want := drectveOf(t, back), drectveOf(t, regular); got != want {
			t.Errorf("%s: directives %q, want %q", name, got, want)
		}
	}
	// Archives of bigobj members get the same index.
	in := testArchive(ar.Member{Name: "one.obj", Data: toBigObj(t, coffFixture(""))})
	defined, err := Defined(in)
	if err != nil || len(defined) != 5 {
		t.Fatalf("Defined = %q, %v", defined, err)
	}
	if _, _, err := Edit(in, Edits{Rename: Prefix(defined, "p_")}); err != nil {
		t.Fatal(err)
	}
}

// drectveOf returns the .drectve contents, or "" when the edit removed it.
func drectveOf(t *testing.T, data []byte) string {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if s := f.Section(".drectve"); s != nil {
		b, _ := s.Data()
		return string(b)
	}
	return ""
}

func TestBigObjSectionNumbers(t *testing.T) {
	l := coffLayout{big: true, header: coffBigHeader, symSize: coffBigSymbolSize}
	e := make([]byte, coffBigSymbolSize)
	l.putSymbolSection(e, 70000)
	if l.symbolSection(e) != 70000 {
		t.Fatal("32-bit section number")
	}
	l.putSymbolSection(e, -2)
	if l.symbolSection(e) != -2 {
		t.Fatal("debug section number")
	}
	aux := make([]byte, coffBigSymbolSize)
	l.putAuxNumber(aux, 0x12345)
	if l.auxNumber(aux) != 0x12345 || binary.LittleEndian.Uint16(aux[16:]) != 1 {
		t.Fatal("associative number high half")
	}
}
