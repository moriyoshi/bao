package symedit

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

// machoTo32 rewrites a 64-bit test object as an i386 one: a 28-byte header,
// LC_SEGMENT with 68-byte section headers and 12-byte nlist entries. The
// load commands shrink and are padded back to their old end, and the
// symbol table shrinks in place, so every other file offset stays valid.
func machoTo32(t *testing.T, data []byte) []byte {
	t.Helper()
	le := binary.LittleEndian
	ncmds, sizeofcmds := le.Uint32(data[16:]), int(le.Uint32(data[20:]))
	out := bytes.Clone(data)
	var cmds []byte
	symtab := -1
	for i, off := uint32(0), machoHeader64; i < ncmds; i++ {
		c := data[off : off+int(le.Uint32(data[off+4:]))]
		off += len(c)
		if le.Uint32(c) != lcSegment64 {
			if le.Uint32(c) == lcSymtab {
				symtab = 28 + len(cmds)
			}
			cmds = append(cmds, c...)
			continue
		}
		n := int(le.Uint32(c[64:]))
		seg := make([]byte, 56)
		le.PutUint32(seg, 0x1)
		copy(seg[8:24], c[8:24])
		for _, f := range [][2]int{{24, 24}, {28, 32}, {32, 40}, {36, 48}} {
			le.PutUint32(seg[f[0]:], uint32(le.Uint64(c[f[1]:])))
		}
		copy(seg[40:56], c[56:72])
		for j := 0; j < n; j++ {
			h := c[72+80*j:]
			s := make([]byte, 68)
			copy(s, h[:32])
			le.PutUint32(s[32:], uint32(le.Uint64(h[32:])))
			le.PutUint32(s[36:], uint32(le.Uint64(h[40:])))
			copy(s[40:68], h[48:76])
			seg = append(seg, s...)
		}
		le.PutUint32(seg[4:], uint32(len(seg)))
		cmds = append(cmds, seg...)
	}
	le.PutUint32(out, 0xfeedface)
	le.PutUint32(out[4:], 7) // CPU_TYPE_I386
	le.PutUint32(out[8:], 3)
	le.PutUint32(out[20:], uint32(len(cmds)))
	copy(out[28:], cmds)
	clear(out[28+len(cmds) : machoHeader64+sizeofcmds])
	if symtab >= 0 {
		symoff, nsyms := le.Uint32(out[symtab+8:]), int(le.Uint32(out[symtab+12:]))
		table := make([]byte, 0, 12*nsyms)
		for i := 0; i < nsyms; i++ {
			e := data[int(symoff)+16*i:]
			table = append(append(table, e[:8]...), le.AppendUint32(nil, uint32(le.Uint64(e[8:])))...)
		}
		copy(out[symoff:], table)
	}
	return out
}

func TestMachO32Edits(t *testing.T) {
	for name, c := range map[string]struct {
		in []byte
		e  Edits
	}{
		"wrap and rename": {machoFixture(), Edits{Wrap: []string{"PyList_New", "malloc"}, Rename: map[string]string{"XML_Parse": "ext_XML_Parse", "helper": "helper2"}}},
		"bindings":        {machoFixture(), Edits{Visibility: Visibility{KeepGlobal: matcher(t, true, "Py*", "!Py_Internal*"), LocalizeHidden: true}}},
		"remove section":  {machoSectionFixture(), Edits{RemoveSection: matcher(t, true, "__DWARF,*")}},
		"add symbols":     {machoSectionFixture(), Edits{AddSymbols: addSymbols(t, "alias=__LD,__compact_unwind:8,function", "absent=__TEXT,__text:4,hidden", "f_alias=@f:4")}},
	} {
		want, wn, err := Edit(c.in, c.e)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, gn, err := Edit(machoTo32(t, c.in), c.e)
		if err != nil || gn != wn {
			t.Fatalf("%s: 32-bit: %d edits, %v; want %d", name, gn, err, wn)
		}
		if binary.LittleEndian.Uint32(got) != 0xfeedface {
			t.Fatalf("%s: result is not 32-bit", name)
		}
		if g, w := readMachO(t, got), readMachO(t, want); !reflect.DeepEqual(g, w) {
			t.Errorf("%s: symbols, relocations or indirect table differ:\n%+v\n%+v", name, g, w)
		}
		if g, w := readMachOLayout(t, got), readMachOLayout(t, want); !reflect.DeepEqual(g.sections, w.sections) || !reflect.DeepEqual(g.symbols, w.symbols) || !reflect.DeepEqual(g.local, w.local) {
			t.Errorf("%s: layout differs:\n%+v\n%+v", name, g, w)
		}
	}
}

// A scattered relocation names an address: the symbol there cannot be
// stripped, and its section cannot go. -strip-unneeded keeps every 32-bit
// section symbol, since section-relative relocations also reach code by
// address.
func TestMachO32ScatteredRelocations(t *testing.T) {
	in := machoTo32(t, testMachO([]testNlist{
		{name: "_label", typ: local, sect: machoUnwind, value: 128 + 8},
		{name: "_other", typ: local, sect: machoUnwind, value: 128 + 16},
	}))
	le := binary.LittleEndian
	// Give __text one scattered GENERIC_RELOC_VANILLA naming _label's address.
	text := in[28+56:]
	reloff := uint32(len(in))
	in = le.AppendUint32(in, relocScattered|2<<28|8)
	in = le.AppendUint32(in, 128+8)
	text = in[28+56:]
	le.PutUint32(text[48:], reloff)
	le.PutUint32(text[52:], 1)
	if _, _, err := Edit(in, Edits{Visibility: Visibility{Strip: matcher(t, false, "label")}}); err == nil || !strings.Contains(err.Error(), "not stripping symbol label") {
		t.Fatalf("strip the scattered target: %v", err)
	}
	out, _, err := Edit(in, Edits{Visibility: Visibility{Strip: matcher(t, false, "other")}})
	if err != nil {
		t.Fatal(err)
	}
	if v := readMachO(t, out); !reflect.DeepEqual(v.symbols, []string{"_label:L"}) {
		t.Fatalf("symbols = %q", v.symbols)
	}
	out, _, err = Edit(in, Edits{Visibility: Visibility{StripUnneeded: true}})
	if err != nil {
		t.Fatal(err)
	}
	if v := readMachO(t, out); !reflect.DeepEqual(v.symbols, []string{"_label:L", "_other:L"}) {
		t.Fatalf("-strip-unneeded removed a 32-bit section symbol: %q", v.symbols)
	}
	if _, _, err := Edit(in, Edits{RemoveSection: matcher(t, false, "__LD,__compact_unwind")}); err == nil || !strings.Contains(err.Error(), "a kept scattered relocation in __TEXT,__text refers to it") {
		t.Fatalf("remove target: %v", err)
	}
}

// testFat builds a universal file from slices, with FAT_MAGIC or
// FAT_MAGIC_64 and each slice aligned to 2^12.
func testFat(t *testing.T, wide bool, slices ...[]byte) []byte {
	t.Helper()
	be := binary.BigEndian
	entry, magic := 20, uint32(fatMagic)
	if wide {
		entry, magic = 32, fatMagic64
	}
	out := be.AppendUint32(be.AppendUint32(nil, magic), uint32(len(slices)))
	out = append(out, make([]byte, entry*len(slices))...)
	for i, s := range slices {
		for len(out)%4096 != 0 {
			out = append(out, 0)
		}
		cpu := binary.LittleEndian.Uint32(s[4:])
		if isArchive(s) {
			cpu = 0x0100000c
		}
		h := out[8+i*entry:]
		be.PutUint32(h, cpu)
		if wide {
			be.PutUint64(h[8:], uint64(len(out)))
			be.PutUint64(h[16:], uint64(len(s)))
			be.PutUint32(h[24:], 12)
		} else {
			be.PutUint32(h[8:], uint32(len(out)))
			be.PutUint32(h[12:], uint32(len(s)))
			be.PutUint32(h[16:], 12)
		}
		out = append(out, s...)
	}
	return out
}

func TestMachOFat(t *testing.T) {
	user := testMachO([]testNlist{{name: "_PyList_New", typ: undef, text: true}})
	lib := testArchive(ar.Member{Name: "one.o", Data: machoFixture()}, ar.Member{Name: "user.o", Data: user})
	e := Edits{Wrap: []string{"malloc"}, Rename: map[string]string{"XML_Parse": "ext_XML_Parse"}}
	for _, wide := range []bool{false, true} {
		slices := [][]byte{machoTo32(t, machoFixture()), lib}
		in := testFat(t, wide, slices...)
		defined, err := Defined(in)
		if err != nil || !reflect.DeepEqual(defined, []string{"PyList_New", "Py_hidden", "XML_Parse", "tentative"}) {
			t.Fatalf("Defined = %q, %v", defined, err)
		}
		out, n, err := Edit(in, e)
		if err != nil {
			t.Fatal(err)
		}
		parts, fs, gotWide, err := fatSlices(out)
		if err != nil || gotWide != wide || len(parts) != 2 {
			t.Fatalf("fatSlices = %d, %v, %v", len(parts), gotWide, err)
		}
		total := 0
		for i, part := range parts {
			want, wn, err := Edit(slices[i], e)
			if err != nil || !bytes.Equal(part, want) {
				t.Fatalf("slice %d differs from editing it alone: %v", i, err)
			}
			if fs[i].offset%4096 != 0 || fs[i].align != 12 {
				t.Fatalf("slice %d at %#x align %d", i, fs[i].offset, fs[i].align)
			}
			total += wn
		}
		if n != total {
			t.Fatalf("edited %d, want %d", n, total)
		}
	}
	// A Java class file shares FAT_MAGIC but not a plausible count.
	if isFat([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34}) {
		t.Fatal("class file taken for a universal file")
	}
	bad := testFat(t, false, machoFixture())
	binary.BigEndian.PutUint32(bad[8+12:], 1<<30)
	if _, _, err := Edit(bad, e); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("truncated slice: %v", err)
	}
}

// An alias of a 32-bit ARM Thumb function is a Thumb symbol too.
func TestMachOARMThumbAlias(t *testing.T) {
	in := machoTo32(t, testMachO([]testNlist{{name: "_thumb", typ: global, desc: nArmThumbDef}}))
	binary.LittleEndian.PutUint32(in[4:], cpuARM)
	out, _, err := Edit(in, Edits{AddSymbols: addSymbols(t, "alias=@thumb:0,function", "inside=@thumb:2")})
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseMachO(out)
	if err != nil {
		t.Fatal(err)
	}
	desc := map[string]uint16{}
	for _, s := range f.symbols {
		desc[s.name] = s.desc
	}
	// An offset into the function names no function entry.
	if desc["_alias"]&nArmThumbDef == 0 || desc["_inside"]&nArmThumbDef != 0 {
		t.Fatalf("desc = %v", desc)
	}
}
