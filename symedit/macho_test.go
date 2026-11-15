package symedit

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

type testNlist struct {
	name  string
	typ   byte
	desc  uint16
	value uint64
	// text, debug and unwind list the sections whose relocations name it.
	text, debug, unwind bool
	indirect            bool
}

// Section numbers of testMachO (1-based, as n_sect counts them).
const (
	machoText   = 1
	machoDebug  = 2
	machoUnwind = 3
)

// testMachO builds an arm64 MH_OBJECT whose symbols are in table order,
// locals first, as given. Each section's extern ARM64_RELOC_UNSIGNED
// relocations name the symbols that list it, and the indirect symbol table
// lists the indirect ones followed by an INDIRECT_SYMBOL_LOCAL entry.
func testMachO(symbols []testNlist) []byte {
	le := binary.LittleEndian
	strtab := []byte{' ', 0}
	var table []byte
	var relocs [3][]byte
	var indirect []byte
	locals, defs := 0, 0
	for i, s := range symbols {
		e := make([]byte, nlistSize)
		if s.name != "" {
			le.PutUint32(e, uint32(len(strtab)))
			strtab = append(append(strtab, s.name...), 0)
		}
		e[4] = s.typ
		if s.typ&nType == nSect {
			e[5] = machoText
		}
		le.PutUint16(e[6:], s.desc)
		le.PutUint64(e[8:], s.value)
		table = append(table, e...)
		switch {
		case s.typ&nExt == 0 || s.typ&nStab != 0:
			locals++
		case s.typ&nType != nUndf:
			defs++
		}
		for j, on := range []bool{s.text, s.debug, s.unwind} {
			if on {
				r := make([]byte, 8)
				le.PutUint32(r, uint32(8*len(relocs[j])/8))
				le.PutUint32(r[4:], uint32(i)|3<<25|relocExtern)
				relocs[j] = append(relocs[j], r...)
			}
		}
		if s.indirect {
			indirect = le.AppendUint32(indirect, uint32(i))
		}
	}
	indirect = le.AppendUint32(indirect, indirectLocal)
	for len(strtab)%8 != 0 {
		strtab = append(strtab, 0)
	}
	names := [3][2]string{{"__text", "__TEXT"}, {"__debug_info", "__DWARF"}, {"__compact_unwind", "__LD"}}
	flags := [3]uint32{0x80000400, sAttrDebug, 0x02000000 &^ sAttrDebug}
	sizeofcmds := 72 + 3*80 + 24 + 80
	contents := machoHeader64 + sizeofcmds
	data := make([]byte, contents)
	// 64 bytes of section contents, then relocations, symbols and strings.
	sectionData := contents
	data = append(data, make([]byte, 3*64)...)
	reloff := [3]int{}
	for j := range relocs {
		reloff[j] = len(data)
		data = append(data, relocs[j]...)
	}
	indoff := len(data)
	data = append(data, indirect...)
	symoff := len(data)
	data = append(data, table...)
	stroff := len(data)
	data = append(data, strtab...)
	le.PutUint32(data, machoMagic64)
	le.PutUint32(data[4:], 0x0100000c) // CPU_TYPE_ARM64
	le.PutUint32(data[12:], mhObject)
	le.PutUint32(data[16:], 3)
	le.PutUint32(data[20:], uint32(sizeofcmds))
	le.PutUint32(data[24:], 0x2000) // MH_SUBSECTIONS_VIA_SYMBOLS
	c := data[machoHeader64:]
	le.PutUint32(c, lcSegment64)
	le.PutUint32(c[4:], 72+3*80)
	le.PutUint64(c[32:], 3*64)
	le.PutUint64(c[40:], uint64(sectionData))
	le.PutUint64(c[48:], 3*64)
	le.PutUint32(c[56:], 7)
	le.PutUint32(c[60:], 7)
	le.PutUint32(c[64:], 3)
	for j := range names {
		h := c[72+80*j:]
		copy(h, names[j][0])
		copy(h[16:], names[j][1])
		le.PutUint64(h[32:], uint64(64*j))
		le.PutUint64(h[40:], 64)
		le.PutUint32(h[48:], uint32(sectionData+64*j))
		le.PutUint32(h[56:], uint32(reloff[j]))
		le.PutUint32(h[60:], uint32(len(relocs[j])/8))
		le.PutUint32(h[64:], flags[j])
	}
	c = c[72+3*80:]
	le.PutUint32(c, lcSymtab)
	le.PutUint32(c[4:], 24)
	le.PutUint32(c[8:], uint32(symoff))
	le.PutUint32(c[12:], uint32(len(symbols)))
	le.PutUint32(c[16:], uint32(stroff))
	le.PutUint32(c[20:], uint32(len(strtab)))
	c = c[24:]
	le.PutUint32(c, lcDysymtab)
	le.PutUint32(c[4:], 80)
	le.PutUint32(c[12:], uint32(locals))
	le.PutUint32(c[16:], uint32(locals))
	le.PutUint32(c[20:], uint32(defs))
	le.PutUint32(c[24:], uint32(locals+defs))
	le.PutUint32(c[28:], uint32(len(symbols)-locals-defs))
	le.PutUint32(c[56:], uint32(indoff))
	le.PutUint32(c[60:], uint32(len(indirect)/4))
	return data
}

const (
	local  = nSect
	global = nSect | nExt
	hidden = nSect | nExt | nPext
	undef  = nUndf | nExt
)

func machoFixture() []byte {
	return testMachO([]testNlist{
		{name: "main.c", typ: 0x64}, // N_SO stab
		{name: "ltmp0", typ: local, text: true},
		{name: "_helper", typ: local, text: true},
		{name: "_unused", typ: local},
		{name: "_retained", typ: local, desc: nNoDeadStrip},
		{name: "_PyList_New", typ: global, text: true, debug: true, unwind: true},
		{name: "_Py_hidden", typ: hidden, text: true},
		{name: "_XML_Parse", typ: global, text: true},
		{name: "___real_PyList_New", typ: undef, text: true},
		{name: "_absent", typ: undef},
		{name: "_malloc", typ: undef, text: true, indirect: true},
		{name: "_tentative", typ: undef, value: 8},
	})
}

type machoView struct {
	symbols []string // NAME:KIND, K for local, G global, W weak, H private extern
	relocs  map[string][]string
	ind     []string
	groups  [3]uint32
}

func readMachO(t *testing.T, data []byte) machoView {
	t.Helper()
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var v machoView
	for _, s := range f.Symtab.Syms {
		kind := "L"
		switch {
		case s.Type&nExt == 0:
		case s.Type&nPext != 0:
			kind = "H"
		case s.Desc&(nWeakDef|nWeakRef) != 0:
			kind = "W"
		default:
			kind = "G"
		}
		if s.Type&nStab != 0 {
			kind = "S"
		}
		v.symbols = append(v.symbols, s.Name+":"+kind)
	}
	v.relocs = map[string][]string{}
	for _, sec := range f.Sections {
		for _, r := range sec.Relocs {
			if r.Extern {
				v.relocs[sec.Name] = append(v.relocs[sec.Name], f.Symtab.Syms[r.Value].Name)
			}
		}
	}
	d := f.Dysymtab
	for _, i := range d.IndirectSyms {
		if i&indirectLocal != 0 {
			v.ind = append(v.ind, "LOCAL")
		} else {
			v.ind = append(v.ind, f.Symtab.Syms[i].Name)
		}
	}
	v.groups = [3]uint32{d.Nlocalsym, d.Nextdefsym, d.Nundefsym}
	if d.Ilocalsym != 0 || d.Iextdefsym != d.Nlocalsym || d.Iundefsym != d.Nlocalsym+d.Nextdefsym || int(d.Iundefsym+d.Nundefsym) != len(f.Symtab.Syms) {
		t.Fatalf("dysymtab groups %+v for %d symbols", d.DysymtabCmd, len(f.Symtab.Syms))
	}
	return v
}

func TestMachOWrapAndRename(t *testing.T) {
	in := machoFixture()
	original := bytes.Clone(in)
	out, n, err := Edit(in, Edits{Wrap: []string{"PyList_New", "malloc"}, Rename: map[string]string{"XML_Parse": "ext_XML_Parse", "helper": "helper2"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, original) {
		t.Fatal("input was modified")
	}
	v := readMachO(t, out)
	// __real_PyList_New is bound to the definition and removed. External
	// definitions and undefined symbols are each sorted by name.
	want := []string{"main.c:S", "ltmp0:L", "_helper2:L", "_unused:L", "_retained:L", "_PyList_New:G", "_Py_hidden:H", "_ext_XML_Parse:G", "___wrap_PyList_New:G", "___wrap_malloc:G", "_absent:G", "_tentative:G"}
	if !reflect.DeepEqual(v.symbols, want) || v.groups != [3]uint32{5, 3, 4} {
		t.Fatalf("symbols = %q %v, want %q", v.symbols, v.groups, want)
	}
	// Code calls the wrapper; the real symbol's reference binds to the
	// definition; debug and unwind data keep describing it.
	if want := []string{"ltmp0", "_helper2", "___wrap_PyList_New", "_Py_hidden", "_ext_XML_Parse", "_PyList_New", "___wrap_malloc"}; !reflect.DeepEqual(v.relocs["__text"], want) {
		t.Fatalf("__text relocs = %q, want %q", v.relocs["__text"], want)
	}
	if !reflect.DeepEqual(v.relocs["__debug_info"], []string{"_PyList_New"}) || !reflect.DeepEqual(v.relocs["__compact_unwind"], []string{"_PyList_New"}) {
		t.Fatalf("debug/unwind relocs = %q", v.relocs)
	}
	if !reflect.DeepEqual(v.ind, []string{"___wrap_malloc", "LOCAL"}) {
		t.Fatalf("indirect = %q", v.ind)
	}
	// Two renames, one wrapped import and one bound __real_, plus the two
	// relocations that moved: the call to the wrapper and the __real_ one.
	if n != 6 {
		t.Fatalf("edited %d, want 6", n)
	}
}

func TestMachOVisibility(t *testing.T) {
	in := machoFixture()
	out, _, err := Edit(in, Edits{Visibility: Visibility{
		KeepGlobal:     matcher(t, true, "Py*", "!Py_Internal*"),
		LocalizeHidden: true,
		Weaken:         matcher(t, false, "PyList_New", "malloc"),
		StripUnneeded:  true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v := readMachO(t, out)
	// _Py_hidden matches Py* but is a private extern, so -localize-hidden
	// still applies first. Unreferenced locals and imports go, except stabs and
	// the common symbol and the no-dead-strip one.
	want := []string{"main.c:S", "ltmp0:L", "_helper:L", "_retained:L", "_Py_hidden:L", "_XML_Parse:L", "_PyList_New:W", "___real_PyList_New:G", "_malloc:W", "_tentative:G"}
	if !reflect.DeepEqual(v.symbols, want) {
		t.Fatalf("symbols = %q, want %q", v.symbols, want)
	}
	if want := []string{"ltmp0", "_helper", "_PyList_New", "_Py_hidden", "_XML_Parse", "___real_PyList_New", "_malloc"}; !reflect.DeepEqual(v.relocs["__text"], want) {
		t.Fatalf("__text relocs = %q, want %q", v.relocs["__text"], want)
	}
	if !reflect.DeepEqual(v.ind, []string{"_malloc", "LOCAL"}) {
		t.Fatalf("indirect = %q", v.ind)
	}
	for _, name := range []string{"malloc", "helper", "retained"} {
		if _, _, err := Edit(in, Edits{Visibility: Visibility{Strip: matcher(t, false, name)}}); err == nil || !strings.Contains(err.Error(), "not stripping symbol "+name) {
			t.Errorf("strip %s: %v", name, err)
		}
	}
}

func TestMachOPrefixAndArchive(t *testing.T) {
	user := testMachO([]testNlist{{name: "_PyList_New", typ: undef, text: true}, {name: "_free", typ: undef, text: true}})
	long := "a-member-name-longer-than-sixteen.o"
	in := testArchive(ar.Member{Name: "one.o", Data: machoFixture()}, ar.Member{Name: long, Data: user})
	defined, err := Defined(in)
	if err != nil {
		t.Fatal(err)
	}
	// C names, without Mach-O's underscore; the common symbol is a definition.
	if want := []string{"PyList_New", "Py_hidden", "XML_Parse", "tentative"}; !reflect.DeepEqual(defined, want) {
		t.Fatalf("Defined = %q, want %q", defined, want)
	}
	out, _, err := Edit(in, Edits{Rename: Prefix(defined, "p_")})
	if err != nil {
		t.Fatal(err)
	}
	members, err := ar.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 || members[0].Name != "__.SYMDEF" || members[1].Name != "one.o" || members[2].Name != long {
		t.Fatalf("members = %+v", members)
	}
	for _, m := range members {
		if (len(out)-cap(m.Data))%8 != 0 {
			t.Fatalf("member %s data is not 8-byte aligned", m.Name)
		}
	}
	// ranlib's layout: entries of (string offset, member header offset).
	index := members[0].Data
	size := int(binary.LittleEndian.Uint32(index))
	strtab := index[4+size+4:]
	got := map[string]int{}
	for i := 4; i < 4+size; i += 8 {
		strx := binary.LittleEndian.Uint32(index[i:])
		name := string(strtab[strx : int(strx)+bytes.IndexByte(strtab[strx:], 0)])
		got[name] = int(binary.LittleEndian.Uint32(index[i+4:]))
	}
	want := map[string]int{"_p_PyList_New": members[1].Offset, "_p_Py_hidden": members[1].Offset, "_p_XML_Parse": members[1].Offset}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("index = %v, want %v", got, want)
	}
	v := readMachO(t, members[2].Data)
	if got := append([]string{}, v.symbols...); !sort.StringsAreSorted(got) || !reflect.DeepEqual(got, []string{"_free:G", "_p_PyList_New:G"}) {
		t.Fatalf("second member symbols = %q", got)
	}
	// Localizing a definition another member uses breaks the archive.
	if _, _, err := Edit(in, Edits{Visibility: Visibility{Localize: matcher(t, false, "PyList_New")}}); err == nil || !strings.Contains(err.Error(), long+" refers to PyList_New") {
		t.Fatalf("Edit = %v", err)
	}
}

func TestMachORejects(t *testing.T) {
	exec := machoFixture()
	binary.LittleEndian.PutUint32(exec[12:], 2) // MH_EXECUTE
	fat := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}
	thin32 := machoFixture()
	binary.LittleEndian.PutUint32(thin32, 0xfeedface)
	for name, in := range map[string][]byte{"executable": exec, "universal": fat, "32-bit": thin32} {
		if _, _, err := Edit(in, Edits{Wrap: []string{"malloc"}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := Edit(testArchive(ar.Member{Name: "a.o", Data: machoFixture()}, ar.Member{Name: "b.o", Data: fixture()}), Edits{Wrap: []string{"malloc"}}); err == nil || !strings.Contains(err.Error(), "mixes") {
		t.Errorf("mixed archive: %v", err)
	}
}
