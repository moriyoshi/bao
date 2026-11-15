package symedit

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
	internalar "github.com/moriyoshi/bao/internal/ar"
)

type testCOFFSymbol struct {
	name    string
	section int16
	class   byte
	value   uint32
	// text, debug and pdata list the sections whose relocations name it.
	text, debug, pdata bool
	// tag names a weak external's default symbol.
	tag string
	// addrsig lists the symbol in .llvm_addrsig.
	addrsig bool
}

// Section numbers of testCOFF.
const (
	coffText    = 1
	coffDebug   = 2
	coffPdata   = 3
	coffDrectve = 4
	coffAddrsig = 5
	coffComdatS = 6
	coffAssocS  = 7
)

// testCOFF builds an amd64 COFF object: a section definition symbol with one
// auxiliary record for each section, then the given symbols. .text$c is a
// COMDAT section, and .pdata$c is associated with it.
func testCOFF(symbols []testCOFFSymbol, directives string) []byte {
	le := binary.LittleEndian
	names := []string{".text", ".debug$S", ".pdata", ".drectve", ".llvm_addrsig", ".text$c", ".pdata$c"}
	flags := []uint32{0x60000020, 0x42100040, 0x40300040, 0x00100a00, 0x00100800, 0x60001020, 0x40301040}
	strtab := []byte{0, 0, 0, 0}
	name := func(entry []byte, s string) {
		if len(s) <= 8 {
			copy(entry, s)
			return
		}
		le.PutUint32(entry[4:], uint32(len(strtab)))
		strtab = append(append(strtab, s...), 0)
	}
	// Record indices: sections take two records each.
	index := map[string]int{}
	next := 2 * len(names)
	for _, s := range symbols {
		index[s.name] = next
		next++
		if s.tag != "" {
			next++
		}
	}
	var table []byte
	var relocs [3][]byte
	var addrsig []byte
	record := func(entry []byte) { table = append(table, entry...) }
	for i, n := range names {
		e := make([]byte, coffSymbolSize)
		name(e, n)
		le.PutUint16(e[12:], uint16(i+1))
		e[16], e[17] = coffClassStatic, 1
		record(e)
		aux := make([]byte, coffSymbolSize)
		switch i + 1 {
		case coffComdatS:
			aux[14] = 2 // IMAGE_COMDAT_SELECT_ANY
		case coffAssocS:
			le.PutUint16(aux[12:], coffComdatS)
			aux[14] = coffSelectAssociative
		}
		record(aux)
	}
	for _, s := range symbols {
		e := make([]byte, coffSymbolSize)
		name(e, s.name)
		le.PutUint32(e[8:], s.value)
		le.PutUint16(e[12:], uint16(s.section))
		e[16] = s.class
		if s.tag != "" {
			e[17] = 1
		}
		record(e)
		if s.tag != "" {
			aux := make([]byte, coffSymbolSize)
			le.PutUint32(aux, uint32(index[s.tag]))
			le.PutUint32(aux[4:], 3) // IMAGE_WEAK_EXTERN_SEARCH_ALIAS
			record(aux)
		}
		for j, on := range []bool{s.text, s.debug, s.pdata} {
			if on {
				r := make([]byte, coffRelocSize)
				le.PutUint32(r, uint32(len(relocs[j])))
				le.PutUint32(r[4:], uint32(index[s.name]))
				le.PutUint16(r[8:], []uint16{4, 0xb, 3}[j])
				relocs[j] = append(relocs[j], r...)
			}
		}
		if s.addrsig {
			addrsig = binary.AppendUvarint(addrsig, uint64(index[s.name]))
		}
	}
	le.PutUint32(strtab, uint32(len(strtab)))
	contents := [][]byte{make([]byte, 16), make([]byte, 16), make([]byte, 16), []byte(directives), addrsig, make([]byte, 16), make([]byte, 16)}
	out := make([]byte, coffFileHeader+len(names)*coffSectionHeader)
	for i := range names {
		h := out[coffFileHeader+i*coffSectionHeader:]
		if len(names[i]) > 8 {
			// Long section names refer to the string table as /OFFSET.
			copy(h, "/"+strconv.Itoa(bytes.Index(strtab, append([]byte(names[i]), 0))))
		} else {
			copy(h, names[i])
		}
		le.PutUint32(h[16:], uint32(len(contents[i])))
		le.PutUint32(h[20:], uint32(len(out)))
		out = append(out, contents[i]...)
		h = out[coffFileHeader+i*coffSectionHeader:]
		if i < 3 {
			le.PutUint32(h[24:], uint32(len(out)))
			le.PutUint16(h[32:], uint16(len(relocs[i])/coffRelocSize))
			out = append(out, relocs[i]...)
			h = out[coffFileHeader+i*coffSectionHeader:]
		}
		le.PutUint32(h[36:], flags[i])
	}
	le.PutUint16(out, coffMachineAMD64)
	le.PutUint16(out[2:], uint16(len(names)))
	le.PutUint32(out[8:], uint32(len(out)))
	le.PutUint32(out[12:], uint32(len(table)/coffSymbolSize))
	return append(append(out, table...), strtab...)
}

const (
	ext    = coffClassExternal
	static = coffClassStatic
	weak   = coffClassWeakExternal
)

func coffFixture(directives string) []byte {
	return testCOFF([]testCOFFSymbol{
		{name: "@feat.00", section: -1, class: static},
		{name: "helper", section: coffText, class: static, text: true},
		{name: "unused", section: coffText, class: static},
		{name: "comdat_key", section: coffComdatS, class: ext},
		{name: "PyList_New", section: coffText, class: ext, text: true, debug: true, pdata: true, addrsig: true},
		{name: "XML_Parse", section: coffText, class: ext, text: true, addrsig: true},
		{name: "__real_PyList_New", class: ext, text: true},
		{name: "absent", class: ext},
		{name: "malloc", class: ext, text: true},
		{name: "__imp_free", class: ext, text: true},
		{name: "__imp_dep", class: ext, text: true},
		{name: "tentative", class: ext, value: 8},
		{name: ".weak.opt.default", section: coffText, class: ext},
		{name: "opt", class: weak, tag: ".weak.opt.default", text: true},
		{name: "after_weak", section: coffText, class: ext, text: true, addrsig: true},
	}, directives)
}

type coffView struct {
	symbols []string // NAME:CLASS, with E external, S static, W weak external
	relocs  map[string][]string
	addrsig []string
	tags    map[string]string
}

func readCOFF(t *testing.T, data []byte) coffView {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	v := coffView{relocs: map[string][]string{}, tags: map[string]string{}}
	names := map[uint32]string{}
	for i := 0; i < len(f.COFFSymbols); i++ {
		s := f.COFFSymbols[i]
		name, err := s.FullName(f.StringTable)
		if err != nil {
			t.Fatal(err)
		}
		names[uint32(i)] = name
		i += int(s.NumberOfAuxSymbols)
	}
	for i := 0; i < len(f.COFFSymbols); i++ {
		s := f.COFFSymbols[i]
		if s.SectionNumber > 0 && int(s.SectionNumber) <= len(f.Sections) && f.Sections[s.SectionNumber-1].Name == names[uint32(i)] {
			i += int(s.NumberOfAuxSymbols)
			continue
		}
		v.symbols = append(v.symbols, names[uint32(i)]+":"+map[byte]string{ext: "E", static: "S", weak: "W"}[s.StorageClass])
		if s.StorageClass == weak {
			tag := binary.LittleEndian.Uint32(data[le.Uint32(data[8:])+uint32(i+1)*coffSymbolSize:])
			v.tags[names[uint32(i)]] = names[tag]
		}
		i += int(s.NumberOfAuxSymbols)
	}
	for _, sec := range f.Sections {
		for _, r := range sec.Relocs {
			v.relocs[sec.Name] = append(v.relocs[sec.Name], names[r.SymbolTableIndex])
		}
		if sec.Name == ".llvm_addrsig" {
			b, _ := sec.Data()
			for len(b) > 0 {
				x, n := binary.Uvarint(b)
				b = b[n:]
				v.addrsig = append(v.addrsig, names[uint32(x)])
			}
		}
	}
	return v
}

func TestCOFFWrapAndRename(t *testing.T) {
	in := coffFixture("")
	original := bytes.Clone(in)
	out, n, err := Edit(in, Edits{Wrap: []string{"PyList_New", "malloc", "free"}, Rename: map[string]string{"XML_Parse": "ext_XML_Parse", "dep": "dep2", "helper": "helper2"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, original) {
		t.Fatal("input was modified")
	}
	v := readCOFF(t, out)
	want := []string{"@feat.00:S", "helper2:S", "unused:S", "comdat_key:E", "PyList_New:E", "ext_XML_Parse:E", "absent:E", "__wrap_malloc:E", "__imp___wrap_free:E", "__imp_dep2:E", "tentative:E", ".weak.opt.default:E", "opt:W", "after_weak:E", "__wrap_PyList_New:E"}
	if !reflect.DeepEqual(v.symbols, want) {
		t.Fatalf("symbols = %q, want %q", v.symbols, want)
	}
	if want := []string{"helper2", "__wrap_PyList_New", "ext_XML_Parse", "PyList_New", "__wrap_malloc", "__imp___wrap_free", "__imp_dep2", "opt", "after_weak"}; !reflect.DeepEqual(v.relocs[".text"], want) {
		t.Fatalf(".text relocs = %q, want %q", v.relocs[".text"], want)
	}
	if !reflect.DeepEqual(v.relocs[".debug$S"], []string{"PyList_New"}) || !reflect.DeepEqual(v.relocs[".pdata"], []string{"PyList_New"}) {
		t.Fatalf("debug/pdata relocs = %q", v.relocs)
	}
	// Removing __real_PyList_New renumbered the records after it.
	if !reflect.DeepEqual(v.addrsig, []string{"PyList_New", "ext_XML_Parse", "after_weak"}) || v.tags["opt"] != ".weak.opt.default" {
		t.Fatalf("addrsig = %q, tags = %v", v.addrsig, v.tags)
	}
	// Five renames and the bound __real_, plus two moved relocations.
	if n != 8 {
		t.Fatalf("edited %d, want 8", n)
	}
}

func TestCOFFVisibility(t *testing.T) {
	in := coffFixture("")
	out, _, err := Edit(in, Edits{Visibility: Visibility{
		KeepGlobal:    matcher(t, true, "Py*", "after_*"),
		Globalize:     matcher(t, false, "helper"),
		StripUnneeded: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v := readCOFF(t, out)
	// Unreferenced statics and imports go; @feat.00, the COMDAT key, the
	// weak default and the common symbol stay.
	want := []string{"@feat.00:S", "helper:E", "comdat_key:S", "PyList_New:E", "XML_Parse:S", "__real_PyList_New:E", "malloc:E", "__imp_free:E", "__imp_dep:E", "tentative:E", ".weak.opt.default:E", "opt:W", "after_weak:E"}
	if !reflect.DeepEqual(v.symbols, want) {
		t.Fatalf("symbols = %q, want %q", v.symbols, want)
	}
	if v.tags["opt"] != ".weak.opt.default" || !reflect.DeepEqual(v.addrsig, []string{"PyList_New", "XML_Parse", "after_weak"}) {
		t.Fatalf("tags = %v, addrsig = %q", v.tags, v.addrsig)
	}
	for _, name := range []string{"comdat_key", "helper", "malloc", ".weak.opt.default"} {
		_, _, err := Edit(in, Edits{Visibility: Visibility{Strip: matcher(t, false, name)}})
		if name == ".weak.opt.default" {
			// Not a C name, so never edited.
			if err != nil {
				t.Errorf("strip %s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "not stripping symbol "+name) {
			t.Errorf("strip %s: %v", name, err)
		}
	}
	// COFF has no hidden visibility.
	if _, n, err := Edit(in, Edits{Visibility: Visibility{LocalizeHidden: true}}); err != nil || n != 0 {
		t.Errorf("localize-hidden = %d, %v", n, err)
	}
}

func directives(t *testing.T, data []byte) string {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.Section(".drectve").Data()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCOFFDirectives(t *testing.T) {
	in := coffFixture(" /INCLUDE:PyList_New -exclude-symbols:XML_Parse /ALTERNATENAME:malloc=dlmalloc /DEFAULTLIB:msvcrt")
	for _, tc := range []struct {
		e    Edits
		want string
	}{
		// Explicit renames follow into directives.
		{Edits{Rename: map[string]string{"PyList_New": "p_PyList_New", "XML_Parse": "p_XML_Parse", "malloc": "my_malloc"}}, " /INCLUDE:p_PyList_New -exclude-symbols:p_XML_Parse /ALTERNATENAME:my_malloc=dlmalloc /DEFAULTLIB:msvcrt"},
		// A wrapped name still means the real symbol.
		{Edits{Wrap: []string{"malloc"}}, " /INCLUDE:PyList_New -exclude-symbols:XML_Parse /ALTERNATENAME:malloc=dlmalloc /DEFAULTLIB:msvcrt"},
		// Nothing can export a localized symbol, so its exclusion goes.
		{Edits{Visibility: Visibility{Localize: matcher(t, false, "XML_Parse")}}, " /INCLUDE:PyList_New /ALTERNATENAME:malloc=dlmalloc /DEFAULTLIB:msvcrt"},
	} {
		out, _, err := Edit(in, tc.e)
		if err != nil {
			t.Fatal(err)
		}
		if got := directives(t, out); got != tc.want {
			t.Errorf("%+v: .drectve = %q, want %q", tc.e, got, tc.want)
		}
	}
	for _, e := range []Edits{
		{Visibility: Visibility{Localize: matcher(t, false, "PyList_New")}},
		{Visibility: Visibility{Strip: matcher(t, false, "absent")}, Rename: map[string]string{}},
	} {
		in := coffFixture(" /INCLUDE:PyList_New /ALTERNATENAME:absent=XML_Parse")
		if _, _, err := Edit(in, e); err == nil || !strings.Contains(err.Error(), "no longer export") {
			t.Errorf("%+v: %v", e, err)
		}
	}
}

func TestCOFFArchive(t *testing.T) {
	user := testCOFF([]testCOFFSymbol{{name: "PyList_New", class: ext, text: true}, {name: "__imp_free", class: ext, text: true}}, "")
	long := "a-member-name-longer-than-fifteen.obj"
	in := testArchive(ar.Member{Name: "one.obj", Data: coffFixture("")}, ar.Member{Name: long, Data: user})
	defined, err := Defined(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"PyList_New", "XML_Parse", "after_weak", "comdat_key", "tentative"}; !reflect.DeepEqual(defined, want) {
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
	if len(members) != 5 || members[0].Name != "/" || members[1].Name != "/" || members[2].Name != "//" || members[3].Name != "one.obj" || members[4].Name != long {
		t.Fatalf("members = %+v", members)
	}
	// The second linker member: member offsets, then name-sorted symbols
	// with 1-based member numbers.
	second := members[1].Data
	nm := int(binary.LittleEndian.Uint32(second))
	if nm != 2 || int(binary.LittleEndian.Uint32(second[4:])) != members[3].Offset || int(binary.LittleEndian.Uint32(second[8:])) != members[4].Offset {
		t.Fatalf("second linker member offsets: %x", second[:12])
	}
	ns := int(binary.LittleEndian.Uint32(second[12:]))
	strs := strings.Split(strings.TrimRight(string(second[16+2*ns:]), "\x00"), "\x00")
	if !sort.StringsAreSorted(strs) || len(strs) != ns {
		t.Fatalf("second linker member names = %q", strs)
	}
	got := map[string]uint16{}
	for i, s := range strs {
		got[s] = binary.LittleEndian.Uint16(second[16+2*i:])
	}
	// The weak alias opt, whose default is defined, is indexed as llvm-lib
	// indexes it.
	want := map[string]uint16{"p_PyList_New": 1, "p_XML_Parse": 1, "p_after_weak": 1, "p_comdat_key": 1, "p_tentative": 1, ".weak.opt.default": 1, "opt": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("index = %v, want %v", got, want)
	}
	v := readCOFF(t, members[4].Data)
	if !reflect.DeepEqual(v.symbols, []string{"p_PyList_New:E", "__imp_free:E"}) {
		t.Fatalf("second member symbols = %q", v.symbols)
	}
	// Bao's own COFF member selection reads the result.
	objects, err := internalar.ParseCOFFForMachine(out, coffMachineAMD64)
	if err != nil || len(objects) != 2 {
		t.Fatalf("ParseCOFF = %d, %v", len(objects), err)
	}
	if _, _, err := Edit(in, Edits{Visibility: Visibility{Localize: matcher(t, false, "PyList_New")}}); err == nil || !strings.Contains(err.Error(), long+" refers to PyList_New") {
		t.Fatalf("Edit = %v", err)
	}
}

func TestCOFFRejects(t *testing.T) {
	i386 := coffFixture("")
	binary.LittleEndian.PutUint16(i386, 0x14c)
	bigobj := []byte{0, 0, 0xff, 0xff, 2, 0, 0x64, 0x86}
	short := []byte{0, 0, 0xff, 0xff, 0, 0, 0x64, 0x86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for name, in := range map[string][]byte{"i386": i386, "bigobj": append(bigobj, make([]byte, 60)...), "import": short} {
		if _, _, err := Edit(in, Edits{Wrap: []string{"malloc"}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

type coffLayout struct {
	sections []string
	symbols  []string // NAME:SECTION:VALUE:TYPE, with ABS and UNDEF for others
	assoc    string   // the section .pdata$c is associated with
}

func readCOFFLayout(t *testing.T, data []byte) coffLayout {
	t.Helper()
	readCOFF(t, data)
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var l coffLayout
	for _, s := range f.Sections {
		l.sections = append(l.sections, s.Name)
	}
	symoff := binary.LittleEndian.Uint32(data[8:])
	for i := 0; i < len(f.COFFSymbols); i++ {
		s := f.COFFSymbols[i]
		name, _ := s.FullName(f.StringTable)
		where := "UNDEF"
		switch {
		case s.SectionNumber == -1:
			where = "ABS"
		case s.SectionNumber > 0:
			where = f.Sections[s.SectionNumber-1].Name
		}
		if where == name {
			if name == ".pdata$c" {
				aux := data[symoff+uint32(i+1)*coffSymbolSize:]
				l.assoc = f.Sections[binary.LittleEndian.Uint16(aux[12:])-1].Name
			}
		} else {
			l.symbols = append(l.symbols, name+":"+where+":"+strconv.Itoa(int(s.Value))+":"+strconv.Itoa(int(s.Type)))
		}
		i += int(s.NumberOfAuxSymbols)
	}
	return l
}

func TestCOFFRemoveSection(t *testing.T) {
	in := coffFixture("")
	before := readCOFFLayout(t, in)
	out, n, err := Edit(in, Edits{RemoveSection: matcher(t, true, ".debug$*")})
	if err != nil {
		t.Fatal(err)
	}
	l := readCOFFLayout(t, out)
	if want := []string{".text", ".pdata", ".drectve", ".llvm_addrsig", ".text$c", ".pdata$c"}; !reflect.DeepEqual(l.sections, want) {
		t.Fatalf("sections = %q, want %q", l.sections, want)
	}
	// Symbols keep their sections, now renumbered, and the associative
	// section still follows .text$c. The section and its definition symbol
	// count as edits.
	if !reflect.DeepEqual(l.symbols, before.symbols) || l.assoc != ".text$c" || n != 2 {
		t.Fatalf("symbols = %q, associated with %s, %d edits; want %q", l.symbols, l.assoc, n, before.symbols)
	}
	if v := readCOFF(t, out); len(v.relocs[".text"]) != len(readCOFF(t, in).relocs[".text"]) {
		t.Fatalf("relocations = %v", v.relocs)
	}
	// An associative section goes with its COMDAT section.
	out, _, err = Edit(in, Edits{RemoveSection: matcher(t, false, ".text$c")})
	if err != nil {
		t.Fatal(err)
	}
	l = readCOFFLayout(t, out)
	if want := []string{".text", ".debug$S", ".pdata", ".drectve", ".llvm_addrsig"}; !reflect.DeepEqual(l.sections, want) {
		t.Fatalf("sections = %q, want %q", l.sections, want)
	}
	for _, s := range l.symbols {
		if strings.HasPrefix(s, "comdat_key:") {
			t.Fatalf("comdat_key was kept: %q", l.symbols)
		}
	}
	only, _, err := Edit(in, Edits{OnlySection: matcher(t, false, ".text", ".pdata")})
	if err != nil {
		t.Fatal(err)
	}
	if l := readCOFFLayout(t, only); !reflect.DeepEqual(l.sections, []string{".text", ".pdata"}) || len(l.symbols) != len(before.symbols)-1 {
		t.Fatalf("-only-section: %q %q", l.sections, l.symbols)
	}
	// .pdata names PyList_New, which is defined in .text.
	if _, _, err := Edit(in, Edits{RemoveSection: matcher(t, false, ".text")}); err == nil || !strings.Contains(err.Error(), "cannot remove COFF section .text: a kept relocation, COMDAT section or weak external names PyList_New, defined in it") {
		t.Errorf("remove .text: %v", err)
	}
}

func TestCOFFAddSymbol(t *testing.T) {
	in := coffFixture("")
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
	before := readCOFFLayout(t, in)
	out, n, err := Edit(in, add("alias=.text:4,function", "absent=.text$c:0", "abs=0x40,local"))
	if err != nil {
		t.Fatal(err)
	}
	l := readCOFFLayout(t, out)
	// The undefined absent becomes the definition; the others follow.
	var want []string
	for _, s := range before.symbols {
		if strings.HasPrefix(s, "absent:") {
			s = "absent:.text$c:0:0"
		}
		want = append(want, s)
	}
	want = append(want, "alias:.text:4:32", "abs:ABS:64:0")
	if !reflect.DeepEqual(l.symbols, want) || n != 3 {
		t.Fatalf("symbols = %q (%d edits), want %q", l.symbols, n, want)
	}
	if v := readCOFF(t, out); v.symbols[len(v.symbols)-1] != "abs:S" || v.symbols[len(v.symbols)-2] != "alias:E" {
		t.Fatalf("classes = %q", v.symbols)
	}
	for spec, want := range map[string]string{
		"PyList_New=.text:0":  "already defined",
		"x=.nosuch:0":         "missing COFF section .nosuch",
		"x=.text:0,weak":      "need a default definition",
		"x=.text:0,hidden":    "COFF has none",
		"x=.debug$S:0":        "missing COFF section .debug$S",
		"x=0x100000000,local": "32 bits",
	} {
		e := add(spec)
		e.RemoveSection = matcher(t, false, ".debug$S")
		if _, _, err := Edit(in, e); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

// testCOFFImport builds a short import member declaring NAME from DLL, as
// code or data, imported by name.
func testCOFFImport(name, dll string, data bool) []byte {
	le := binary.LittleEndian
	out := make([]byte, 20)
	le.PutUint16(out[2:], 0xffff)
	le.PutUint16(out[6:], coffMachineAMD64)
	le.PutUint32(out[12:], uint32(len(name)+len(dll)+2))
	typ := uint16(1) << 2 // IMPORT_OBJECT_NAME
	if data {
		typ |= 1
	}
	le.PutUint16(out[18:], typ)
	return append(append(append(append(out, name...), 0), dll...), 0)
}

func TestCOFFImportMembers(t *testing.T) {
	imp := testCOFFImport("malloc", "ucrtbase.dll", false)
	dataImp := testCOFFImport("_environ", "ucrtbase.dll", true)
	in := testArchive(ar.Member{Name: "one.obj", Data: coffFixture("")}, ar.Member{Name: "malloc.obj", Data: imp}, ar.Member{Name: "environ.obj", Data: dataImp})
	// Imports are not definitions that a prefix may rename.
	defined, err := Defined(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"PyList_New", "XML_Parse", "after_weak", "comdat_key", "tentative"}; !reflect.DeepEqual(defined, want) {
		t.Fatalf("Defined = %q, want %q", defined, want)
	}
	out, n, err := Edit(in, Edits{Wrap: []string{"malloc"}, Rename: Prefix(defined, "p_"), Visibility: Visibility{KeepGlobal: matcher(t, true, "p_*", "Py*")}})
	if err != nil || n == 0 {
		t.Fatalf("Edit = %d, %v", n, err)
	}
	members, err := ar.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 5 || !bytes.Equal(members[3].Data, imp) || !bytes.Equal(members[4].Data, dataImp) {
		t.Fatalf("members = %+v", members)
	}
	second := members[1].Data
	ns := int(binary.LittleEndian.Uint32(second[4+4*int(binary.LittleEndian.Uint32(second)):]))
	start := 4 + 4*int(binary.LittleEndian.Uint32(second)) + 4
	strs := strings.Split(strings.TrimRight(string(second[start+2*ns:]), "\x00"), "\x00")
	got := map[string]uint16{}
	for i, s := range strs {
		got[s] = binary.LittleEndian.Uint16(second[start+2*i:])
	}
	// Code imports index the thunk and the slot; data imports the slot.
	for name, member := range map[string]uint16{"malloc": 2, "__imp_malloc": 2, "__imp__environ": 3, "p_PyList_New": 1} {
		if got[name] != member {
			t.Errorf("index %s = %d, want %d (%v)", name, got[name], member, got)
		}
	}
	if _, ok := got["_environ"]; ok {
		t.Errorf("data import indexed its name: %v", got)
	}
	// Bao's COFF member selection still sees the object and the imports.
	if objects, err := internalar.ParseCOFFForMachine(out, coffMachineAMD64); err != nil || len(objects) != 1 {
		t.Fatalf("ParseCOFF = %d, %v", len(objects), err)
	}
	for name, e := range map[string]Edits{
		"-redefine-sym":     {Rename: map[string]string{"malloc": "my_malloc"}},
		"-localize-symbol":  {Visibility: Visibility{Localize: matcher(t, false, "__imp_malloc")}},
		"-strip-symbol":     {Visibility: Visibility{Strip: matcher(t, false, "__imp__environ")}},
		"-globalize-symbol": {Visibility: Visibility{Globalize: matcher(t, false, "malloc")}},
	} {
		if _, _, err := Edit(in, e); err == nil || !strings.Contains(err.Error(), name+" names") || !strings.Contains(err.Error(), "ucrtbase.dll") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The import library's descriptor and thunk objects, which have .idata
	// sections, are left alone too: the linker finds them by these names.
	descriptor := testCOFF([]testCOFFSymbol{{name: "__IMPORT_DESCRIPTOR_ucrtbase", section: coffText, class: ext}}, "")
	copy(descriptor[coffFileHeader:], ".idata$2")
	lib := testArchive(ar.Member{Name: "one.obj", Data: coffFixture("")}, ar.Member{Name: "ucrtbase.dll", Data: descriptor})
	if defined, err := Defined(lib); err != nil || len(defined) != 5 {
		t.Fatalf("Defined = %q, %v", defined, err)
	}
	out, _, err = Edit(lib, Edits{Rename: Prefix([]string{"PyList_New"}, "p_"), Visibility: Visibility{KeepGlobal: matcher(t, false, "p_PyList_New")}})
	if err != nil {
		t.Fatal(err)
	}
	if members, err := ar.Parse(out); err != nil || !bytes.Equal(members[len(members)-1].Data, descriptor) {
		t.Fatalf("descriptor was edited: %v", err)
	}
	if _, _, err := Edit(descriptor, Edits{Visibility: Visibility{Localize: matcher(t, false, "__IMPORT_DESCRIPTOR_ucrtbase")}}); err == nil || !strings.Contains(err.Error(), "-localize-symbol names __IMPORT_DESCRIPTOR_ucrtbase, which an import library descriptor defines") {
		t.Errorf("descriptor localize: %v", err)
	}
	// A lone import member has nothing to edit.
	if out, n, err := Edit(imp, Edits{Wrap: []string{"malloc"}, RemoveSection: matcher(t, false, ".text")}); err != nil || n != 0 || !bytes.Equal(out, imp) {
		t.Fatalf("lone import: %d, %v", n, err)
	}
}

func TestCOFFAddSymbolAtSymbol(t *testing.T) {
	in := coffFixture("")
	// comdat_key is in .text$c; the target's section is used even where a
	// section name would be ambiguous.
	out, _, err := Edit(in, Edits{AddSymbols: addSymbols(t, "key_alias=@comdat_key:2,function", "helper_alias=@helper:1")})
	if err != nil {
		t.Fatal(err)
	}
	l := readCOFFLayout(t, out)
	have := map[string]bool{}
	for _, s := range l.symbols {
		have[s] = true
	}
	if !have["key_alias:.text$c:2:32"] || !have["helper_alias:.text:1:0"] {
		t.Fatalf("symbols = %q", l.symbols)
	}
	for spec, want := range map[string]string{
		"x=@malloc:0":    "does not define",
		"x=@tentative:0": "does not define",
	} {
		if _, _, err := Edit(in, Edits{AddSymbols: addSymbols(t, spec)}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", spec, err)
		}
	}
	e := Edits{AddSymbols: addSymbols(t, "x=@comdat_key:0"), RemoveSection: matcher(t, false, ".text$c")}
	if _, _, err := Edit(in, e); err == nil || !strings.Contains(err.Error(), "whose section is removed") {
		t.Errorf("removed target: %v", err)
	}
}

func TestCOFFWeaken(t *testing.T) {
	in := coffFixture("")
	out, n, err := Edit(in, Edits{Visibility: Visibility{Weaken: matcher(t, false, "PyList_New", "absent", "comdat_key")}})
	if err != nil {
		t.Fatal(err)
	}
	// Two weakened symbols; the COMDAT key, selection ANY, is already
	// link-once.
	if n != 2 {
		t.Fatalf("edited %d, want 2", n)
	}
	v := readCOFF(t, out)
	// The first strong external definition names the defaults.
	def, ref := ".weak.PyList_New.default.comdat_key", ".weak.absent.default.comdat_key"
	if v.tags["PyList_New"] != def || v.tags["absent"] != ref || v.tags["opt"] != ".weak.opt.default" {
		t.Fatalf("tags = %v", v.tags)
	}
	l := readCOFFLayout(t, out)
	have := map[string]bool{}
	for _, s := range l.symbols {
		have[s] = true
	}
	// The definition keeps its section, value and function type; the weak
	// reference's default is absolute zero.
	if !have[def+":.text:0:0"] || !have[ref+":ABS:0:0"] || !have["comdat_key:.text$c:0:0"] {
		t.Fatalf("layout = %q", l.symbols)
	}
	// Code refers to the weak external, so a strong definition elsewhere
	// wins for this object too; unwind and debug data and the
	// address-significance table keep describing this definition.
	if got := v.relocs[".text"]; !reflect.DeepEqual(got, []string{"helper", "PyList_New", "XML_Parse", "__real_PyList_New", "malloc", "__imp_free", "__imp_dep", "opt", "after_weak"}) {
		t.Errorf(".text relocs = %q", got)
	}
	if !reflect.DeepEqual(v.relocs[".debug$S"], []string{def}) || !reflect.DeepEqual(v.relocs[".pdata"], []string{def}) {
		t.Errorf("debug/unwind relocs = %q %q", v.relocs[".debug$S"], v.relocs[".pdata"])
	}
	if !reflect.DeepEqual(v.addrsig, []string{def, "XML_Parse", "after_weak"}) {
		t.Fatalf("addrsig = %q", v.addrsig)
	}
	f, err := parseCOFF(out)
	if err != nil {
		t.Fatal(err)
	}
	index := f.indexNames()
	sort.Strings(index)
	// The weakened definition stays indexed under its name; the weak
	// reference does not.
	for _, name := range []string{"PyList_New", def} {
		if i := sort.SearchStrings(index, name); i == len(index) || index[i] != name {
			t.Errorf("index lacks %s: %q", name, index)
		}
	}
	for _, name := range []string{"absent"} {
		if i := sort.SearchStrings(index, name); i < len(index) && index[i] == name {
			t.Errorf("index has the weak reference %s", name)
		}
	}
	if _, _, err := Edit(in, Edits{Visibility: Visibility{Weaken: matcher(t, false, "tentative")}}); err == nil || !strings.Contains(err.Error(), "cannot weaken COFF symbol tentative") {
		t.Errorf("weaken common: %v", err)
	}
}

// A /Gy function is the key of a COMDAT section with selection
// NODUPLICATES. Weakening renames the key in place, as clang names a weak
// function's section, so it stays the section's first symbol.
func TestCOFFWeakenNoDuplicatesKey(t *testing.T) {
	in := coffFixture("")
	symoff := binary.LittleEndian.Uint32(in[8:])
	in[symoff+uint32(2*coffComdatS-1)*coffSymbolSize+14] = coffSelectNoDuplicates
	out, n, err := Edit(in, Edits{Visibility: Visibility{Weaken: matcher(t, false, "comdat_key")}})
	if err != nil || n != 1 {
		t.Fatalf("Edit = %d, %v", n, err)
	}
	f, err := parseCOFF(out)
	if err != nil {
		t.Fatal(err)
	}
	def := ".weak.comdat_key.default.PyList_New"
	// The key is the first symbol in the section after its definition.
	key := ""
	for _, s := range f.symbols {
		if key == "" && !s.isSection && int(s.section) == coffComdatS {
			key = s.name
		}
	}
	if key != def {
		t.Fatalf("COMDAT key = %q, want %q", key, def)
	}
	if v := readCOFF(t, out); v.tags["comdat_key"] != def {
		t.Fatalf("tags = %v", v.tags)
	}
}
