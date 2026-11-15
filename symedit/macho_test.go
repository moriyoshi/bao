package symedit

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

type testNlist struct {
	name  string
	typ   byte
	desc  uint16
	value uint64
	// sect is the section of an N_SECT symbol, by default machoText.
	sect byte
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
func testMachO(symbols []testNlist) []byte { return buildMachO(symbols, machoExtra{}) }

// machoExtra adds to a testMachO object: section-relative relocations, by
// the ordinal of the section they name, and linker optimization hints of
// one address each.
type machoExtra struct {
	local [3][]uint32
	hints []uint64
}

func buildMachO(symbols []testNlist, extra machoExtra) []byte {
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
			if s.sect != 0 {
				e[5] = s.sect
			}
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
	for j, targets := range extra.local {
		for _, k := range targets {
			r := make([]byte, 8)
			le.PutUint32(r, uint32(len(relocs[j])))
			le.PutUint32(r[4:], k|3<<25)
			relocs[j] = append(relocs[j], r...)
		}
	}
	var hints []byte
	for _, addr := range extra.hints {
		hints = binary.AppendUvarint(append(hints, 1, 1), addr)
	}
	for len(hints)%8 != 0 {
		hints = append(hints, 0)
	}
	ncmds := 3
	for len(strtab)%8 != 0 {
		strtab = append(strtab, 0)
	}
	names := [3][2]string{{"__text", "__TEXT"}, {"__debug_info", "__DWARF"}, {"__compact_unwind", "__LD"}}
	flags := [3]uint32{0x80000400, sAttrDebug, 0x02000000 &^ sAttrDebug}
	sizeofcmds := 72 + 3*80 + 24 + 80
	if len(hints) > 0 {
		ncmds++
		sizeofcmds += 16
	}
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
	hintoff := len(data)
	data = append(data, hints...)
	le.PutUint32(data, machoMagic64)
	le.PutUint32(data[4:], 0x0100000c) // CPU_TYPE_ARM64
	le.PutUint32(data[12:], mhObject)
	le.PutUint32(data[16:], uint32(ncmds))
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
	if len(hints) > 0 {
		c = c[80:]
		le.PutUint32(c, lcLinkerHints)
		le.PutUint32(c[4:], 16)
		le.PutUint32(c[8:], uint32(hintoff))
		le.PutUint32(c[12:], uint32(len(hints)))
	}
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
	// A universal header whose architecture table is missing, a 64-bit
	// body behind the 32-bit magic, and a big-endian object.
	fat := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}
	thin32 := machoFixture()
	binary.LittleEndian.PutUint32(thin32, 0xfeedface)
	bigEndian := machoFixture()
	binary.BigEndian.PutUint32(bigEndian, machoMagic64)
	for name, c := range map[string]struct {
		in   []byte
		want string
	}{
		"executable":            {exec, "not a Mach-O relocatable object"},
		"truncated universal":   {fat, "architecture table is out of range"},
		"64-bit body, 32 magic": {thin32, "out of range"},
		"big-endian":            {bigEndian, "only little-endian Mach-O"},
	} {
		if _, _, err := Edit(c.in, Edits{Wrap: []string{"malloc"}}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, _, err := Edit(testArchive(ar.Member{Name: "a.o", Data: machoFixture()}, ar.Member{Name: "b.o", Data: fixture()}), Edits{Wrap: []string{"malloc"}}); err == nil || !strings.Contains(err.Error(), "mixes") {
		t.Errorf("mixed archive: %v", err)
	}
}

// machoSectionFixture has a symbol in each section, section-relative
// relocations from __text to __compact_unwind and back, and an optimization
// hint in each section.
func machoSectionFixture() []byte {
	return buildMachO([]testNlist{
		{name: "ltmp0", typ: local, text: true},
		{name: "ltmp1", typ: local, sect: machoDebug},
		{name: "ltmp2", typ: local, sect: machoUnwind},
		{name: "_f", typ: global, text: true, unwind: true},
		{name: "_g", typ: global, debug: true},
		{name: "_absent", typ: undef},
		{name: "_ext", typ: undef, text: true},
	}, machoExtra{local: [3][]uint32{{machoUnwind}, nil, {machoText}}, hints: []uint64{0x10, 0x50, 0x90}})
}

type machoSectionView struct {
	sections []string
	symbols  []string // NAME:SECTION:VALUE, with ABS and UNDEF for others
	local    map[string][]uint32
	hints    []uint64
}

func readMachOLayout(t *testing.T, data []byte) machoSectionView {
	t.Helper()
	readMachO(t, data)
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	l := machoSectionView{local: map[string][]uint32{}}
	for _, s := range f.Sections {
		l.sections = append(l.sections, s.Seg+","+s.Name)
		for _, r := range s.Relocs {
			if !r.Extern {
				l.local[s.Name] = append(l.local[s.Name], r.Value)
			}
		}
	}
	for _, s := range f.Symtab.Syms {
		where := "UNDEF"
		switch s.Type & nType {
		case nAbs:
			where = "ABS"
		case nSect:
			where = f.Sections[s.Sect-1].Name
		}
		l.symbols = append(l.symbols, s.Name+":"+where+":"+strconv.FormatUint(s.Value, 10))
	}
	for _, c := range f.Loads {
		raw := c.Raw()
		if binary.LittleEndian.Uint32(raw) != lcLinkerHints {
			continue
		}
		off, size := binary.LittleEndian.Uint32(raw[8:]), binary.LittleEndian.Uint32(raw[12:])
		for b := data[off : off+size]; len(b) > 0 && b[0] != 0; {
			b = b[2:]
			addr, n := binary.Uvarint(b)
			l.hints = append(l.hints, addr)
			b = b[n:]
		}
	}
	return l
}

func TestMachORemoveSection(t *testing.T) {
	in := machoSectionFixture()
	out, n, err := Edit(in, Edits{RemoveSection: matcher(t, true, "__DWARF,*")})
	if err != nil {
		t.Fatal(err)
	}
	l := readMachOLayout(t, out)
	if want := []string{"__TEXT,__text", "__LD,__compact_unwind"}; !reflect.DeepEqual(l.sections, want) {
		t.Fatalf("sections = %q, want %q", l.sections, want)
	}
	// The symbol in the removed section goes; the one after it is renumbered.
	want := []string{"ltmp0:__text:0", "ltmp2:__compact_unwind:0", "_f:__text:0", "_g:__text:0", "_absent:UNDEF:0", "_ext:UNDEF:0"}
	if !reflect.DeepEqual(l.symbols, want) {
		t.Fatalf("symbols = %q, want %q", l.symbols, want)
	}
	if want := map[string][]uint32{"__text": {2}, "__compact_unwind": {1}}; !reflect.DeepEqual(l.local, want) {
		t.Fatalf("section relocations = %v, want %v", l.local, want)
	}
	if want := []uint64{0x10, 0x90}; !reflect.DeepEqual(l.hints, want) {
		t.Fatalf("hints = %#x, want %#x", l.hints, want)
	}
	// One section and the symbol defined in it.
	if n != 2 {
		t.Fatalf("edited %d, want 2", n)
	}
	only, _, err := Edit(in, Edits{OnlySection: matcher(t, false, "__TEXT,__text", "__LD,__compact_unwind")})
	if err != nil || !bytes.Equal(only, out) {
		t.Fatalf("-only-section differs from removing the rest: %v", err)
	}
	for name, want := range map[string]string{
		"__TEXT,__text":         "cannot remove Mach-O section __TEXT,__text: a kept relocation in __LD,__compact_unwind refers to it",
		"__LD,__compact_unwind": "cannot remove Mach-O section __LD,__compact_unwind: a kept relocation in __TEXT,__text refers to it",
	} {
		if _, _, err := Edit(in, Edits{RemoveSection: matcher(t, false, name)}); err == nil || err.Error() != want {
			t.Errorf("remove %s: %v", name, err)
		}
	}
	// A symbol a kept relocation names cannot go with its section.
	text := testMachO([]testNlist{{name: "_f", typ: global, debug: true}})
	if _, _, err := Edit(text, Edits{RemoveSection: matcher(t, false, "__TEXT,__text")}); err == nil || !strings.Contains(err.Error(), "names _f, defined in it") {
		t.Errorf("remove a referenced definition: %v", err)
	}
	// A stub section without a stub size is malformed.
	stubs := testMachO(nil)
	binary.LittleEndian.PutUint32(stubs[machoHeader64+72+64:], 0x80000408)
	if _, _, err := Edit(stubs, Edits{RemoveSection: matcher(t, false, "__TEXT,__text")}); err == nil || !strings.Contains(err.Error(), "does not divide into indirect entries") {
		t.Errorf("remove stubs: %v", err)
	}
}

func TestMachOAddSymbol(t *testing.T) {
	in := machoSectionFixture()
	add := func(specs ...string) Edits {
		var e Edits
		for _, spec := range specs {
			a, err := ParseAddSymbol(spec)
			if err != nil {
				t.Fatal(err)
			}
			e.AddSymbols = append(e.AddSymbols, a)
		}
		return e
	}
	out, n, err := Edit(in, add("alias=__LD,__compact_unwind:8,function", "absent=__TEXT,__text:4,hidden", "abs=0x40,local", "soft=__TEXT,__text:0,weak"))
	if err != nil {
		t.Fatal(err)
	}
	// Values are section offsets, so the alias is at __compact_unwind's
	// address plus 8. The undefined _absent becomes the definition.
	l := readMachOLayout(t, out)
	want := []string{"ltmp0:__text:0", "ltmp1:__debug_info:0", "ltmp2:__compact_unwind:0", "_abs:ABS:64", "_absent:__text:4", "_alias:__compact_unwind:136", "_f:__text:0", "_g:__text:0", "_soft:__text:0", "_ext:UNDEF:0"}
	if !reflect.DeepEqual(l.symbols, want) || n != 4 {
		t.Fatalf("symbols = %q (%d edits), want %q", l.symbols, n, want)
	}
	v := readMachO(t, out)
	if want := []string{"ltmp0:L", "ltmp1:L", "ltmp2:L", "_abs:L", "_absent:H", "_alias:G", "_f:G", "_g:G", "_soft:W", "_ext:G"}; !reflect.DeepEqual(v.symbols, want) {
		t.Fatalf("bindings = %q, want %q", v.symbols, want)
	}
	for spec, want := range map[string]string{
		"f=__TEXT,__text:0":              "already defined",
		"x=__text:0":                     "missing Mach-O section __text",
		"x=__TEXT,__text:0,protected":    "no protected visibility",
		"x=__DWARF,__debug_info:0,local": "missing Mach-O section",
	} {
		e := add(spec)
		e.RemoveSection = matcher(t, false, "__DWARF,__debug_info")
		if _, _, err := Edit(in, e); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", spec, err)
		}
	}
	// Each archive member has the section, so each would define the symbol.
	archive := testArchive(ar.Member{Name: "a.o", Data: in}, ar.Member{Name: "b.o", Data: testMachO(nil)})
	if _, _, err := Edit(archive, add("alias=__TEXT,__text:0")); err == nil || !strings.Contains(err.Error(), "both archive member a.o and b.o") {
		t.Errorf("archive: %v", err)
	}
}

func TestMachOAddSymbolAtSymbol(t *testing.T) {
	in := machoSectionFixture()
	withLocal := buildMachO([]testNlist{{name: "_u", typ: local, sect: machoUnwind, value: 128 + 16}, {name: "_f", typ: global, text: true}}, machoExtra{})
	out, _, err := Edit(withLocal, Edits{AddSymbols: addSymbols(t, "f_alias=@f:4,function", "unwind_alias=@u:8")})
	if err != nil {
		t.Fatal(err)
	}
	// Mach-O values are addresses: the local _u is at 144, 16 bytes into
	// __compact_unwind, so its alias is at 152.
	l := readMachOLayout(t, out)
	have := map[string]bool{}
	for _, s := range l.symbols {
		have[s] = true
	}
	if !have["_f_alias:__text:4"] || !have["_unwind_alias:__compact_unwind:152"] {
		t.Fatalf("symbols = %q", l.symbols)
	}
	e := Edits{AddSymbols: addSymbols(t, "x=@u:0"), RemoveSection: matcher(t, false, "__LD,__compact_unwind")}
	if _, _, err := Edit(withLocal, e); err == nil || !strings.Contains(err.Error(), "whose section is removed") {
		t.Errorf("removed target: %v", err)
	}
	if _, _, err := Edit(in, Edits{AddSymbols: addSymbols(t, "x=@ext:0")}); err == nil || !strings.Contains(err.Error(), "does not define") {
		t.Errorf("undefined target: %v", err)
	}
}

// Pointer and stub sections own runs of the indirect symbol table, from
// reserved1. Removing one drops its run and moves later runs down.
func TestMachORemoveIndirectSections(t *testing.T) {
	in := testMachO([]testNlist{
		{name: "_a", typ: undef, indirect: true},
		{name: "_b", typ: undef, indirect: true},
		{name: "_c", typ: undef, indirect: true},
	})
	le := binary.LittleEndian
	header := func(data []byte, k int) []byte { return data[machoHeader64+72+80*k:] }
	// __compact_unwind: non-lazy pointers to _a and _b; __debug_info: stubs
	// of 8 bytes for _c and the local entry.
	le.PutUint64(header(in, 2)[40:], 16)
	le.PutUint32(header(in, 2)[64:], 0x6)
	le.PutUint32(header(in, 2)[68:], 0)
	le.PutUint64(header(in, 1)[40:], 16)
	le.PutUint32(header(in, 1)[64:], 0x80000408)
	le.PutUint32(header(in, 1)[68:], 2)
	le.PutUint32(header(in, 1)[72:], 8)
	out, _, err := Edit(in, Edits{RemoveSection: matcher(t, false, "__LD,__compact_unwind"), Visibility: Visibility{StripUnneeded: true}})
	if err != nil {
		t.Fatal(err)
	}
	v := readMachO(t, out)
	// _a and _b lose their only references and go with -strip-unneeded.
	if !reflect.DeepEqual(v.ind, []string{"_c", "LOCAL"}) || !reflect.DeepEqual(v.symbols, []string{"_c:G"}) {
		t.Fatalf("indirect = %q, symbols = %q", v.ind, v.symbols)
	}
	if got := le.Uint32(header(out, 1)[68:]); got != 0 {
		t.Fatalf("stub reserved1 = %d, want 0", got)
	}
	// Removing the stubs keeps the pointers' run where it was.
	out, _, err = Edit(in, Edits{RemoveSection: matcher(t, false, "__DWARF,__debug_info")})
	if err != nil {
		t.Fatal(err)
	}
	if v := readMachO(t, out); !reflect.DeepEqual(v.ind, []string{"_a", "_b"}) {
		t.Fatalf("indirect = %q", v.ind)
	}
	if got := le.Uint32(header(out, 1)[68:]); got != 0 {
		t.Fatalf("pointer reserved1 = %d, want 0", got)
	}
}
