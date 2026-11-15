package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

// bound reads back each symbol as NAME:BINDING (L, G or W) in table order,
// with the names that .rela.text, .group and .llvm_addrsig refer to.
type bound struct {
	symbols, relocs, addrsig []string
	signature                string
	firstGlobal              uint32
}

func readBound(t *testing.T, data []byte) bound {
	t.Helper()
	f, symbols, relocs := view(t, data)
	syms, _ := f.Symbols()
	var b bound
	for i, s := range syms {
		b.symbols = append(b.symbols, symbols[i]+":"+map[elf.SymBind]string{elf.STB_LOCAL: "L", elf.STB_GLOBAL: "G", elf.STB_WEAK: "W"}[elf.ST_BIND(s.Info)])
	}
	b.relocs = relocs[".rela.text"]
	b.firstGlobal = f.Sections[symtabIndex].Info
	if f.Sections[groupIndex].Type == elf.SHT_GROUP {
		b.signature = symbols[f.Sections[groupIndex].Info-1]
	}
	data2, _ := f.Sections[addrsigIndex].Data()
	for len(data2) > 0 {
		v, n := binary.Uvarint(data2)
		data2 = data2[n:]
		b.addrsig = append(b.addrsig, symbols[v-1])
	}
	// Each symbol before sh_info must be local and none after it.
	for i, s := range syms {
		if (elf.ST_BIND(s.Info) == elf.STB_LOCAL) != (uint32(i+1) < b.firstGlobal) {
			t.Fatalf("symbol %s at %d is on the wrong side of sh_info %d", s.Name, i+1, b.firstGlobal)
		}
	}
	return b
}

func matcher(t *testing.T, wildcard bool, names ...string) Matcher {
	t.Helper()
	m, err := NewMatcher(names, wildcard)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func visibilityFixture() []byte {
	return testObject([]testSymbol{
		{".text", elf.STB_LOCAL, elf.STT_SECTION, textSection, 0, false, false},
		{"helper", elf.STB_LOCAL, elf.STT_FUNC, textSection, 0, false, false},
		{"$x", elf.STB_LOCAL, elf.STT_NOTYPE, textSection, 0, true, false},
		{"unused", elf.STB_LOCAL, elf.STT_FUNC, textSection, 0, true, false},
		{"PyList_New", elf.STB_GLOBAL, elf.STT_FUNC, textSection, 0, false, false},
		{"_Py_hidden", elf.STB_GLOBAL, elf.STT_FUNC, textSection, elf.STV_HIDDEN, false, true},
		{"XML_Parse", elf.STB_GLOBAL, elf.STT_FUNC, textSection, 0, false, false},
		{"malloc", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, false, false},
		{"absent", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, true, false},
		{"tentative", elf.STB_GLOBAL, elf.STT_OBJECT, elf.SHN_COMMON, elf.STV_HIDDEN, false, false},
	}, "XML_Parse")
}

func TestLocalizeReordersAndRenumbers(t *testing.T) {
	in := visibilityFixture()
	before := readBound(t, in)
	out, n, err := Edit(in, Edits{Visibility: Visibility{LocalizeHidden: true, Localize: matcher(t, false, "XML_Parse")}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("edited %d, want 2", n)
	}
	got := readBound(t, out)
	// The common symbol stays global even though it is hidden.
	want := []string{".text:L", "helper:L", "$x:L", "unused:L", "_Py_hidden:L", "XML_Parse:L", "PyList_New:G", "malloc:G", "absent:G", "tentative:G"}
	if !reflect.DeepEqual(got.symbols, want) {
		t.Fatalf("symbols = %q, want %q", got.symbols, want)
	}
	// Every reference still names the same symbol after renumbering.
	if !reflect.DeepEqual(got.relocs, before.relocs) || got.signature != "_Py_hidden" || !sameSet(got.addrsig, before.addrsig) {
		t.Fatalf("references changed: %+v, before %+v", got, before)
	}
	_, _, relocs := view(t, out)
	if !reflect.DeepEqual(relocs[".rela.debug_info"], []string{"XML_Parse"}) {
		t.Fatalf(".rela.debug_info = %q", relocs[".rela.debug_info"])
	}
	f, _ := elf.NewFile(bytes.NewReader(out))
	if s := f.Sections[shndxIndex]; s.Size != 4*11 {
		t.Fatalf("extended index size %d", s.Size)
	}
}

func sameSet(a, b []string) bool {
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestKeepGlobalWildcardThenStripUnneeded(t *testing.T) {
	in := visibilityFixture()
	out, _, err := Edit(in, Edits{Visibility: Visibility{
		KeepGlobal:    matcher(t, true, "Py*", "!Py*_internal"),
		Globalize:     matcher(t, false, "helper"),
		Weaken:        matcher(t, false, "malloc", "unused"),
		StripUnneeded: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := readBound(t, out)
	// keep-global localizes the other definitions; globalize then wins for
	// helper. Unreferenced local and undefined symbols go, except the section
	// and mapping symbols. A local symbol is never weakened.
	want := []string{".text:L", "$x:L", "_Py_hidden:L", "XML_Parse:L", "helper:G", "PyList_New:G", "malloc:W", "tentative:G"}
	if !reflect.DeepEqual(got.symbols, want) {
		t.Fatalf("symbols = %q, want %q", got.symbols, want)
	}
	// unused and absent were unreferenced; addrsig drops the removed function.
	if want := []string{"helper", "PyList_New", "_Py_hidden", "XML_Parse", "tentative"}; !sameSet(got.addrsig, want) {
		t.Fatalf("addrsig = %q, want %q", got.addrsig, want)
	}
	if got.signature != "_Py_hidden" {
		t.Fatalf("signature = %q", got.signature)
	}
}

func TestStripSymbol(t *testing.T) {
	in := visibilityFixture()
	out, n, err := Edit(in, Edits{Visibility: Visibility{Strip: matcher(t, false, "unused", "absent")}})
	if err != nil || n != 2 {
		t.Fatalf("Edit = %d, %v", n, err)
	}
	if got := readBound(t, out); len(got.symbols) != 8 {
		t.Fatalf("symbols = %q", got.symbols)
	}
	for _, name := range []string{"helper", "_Py_hidden"} {
		_, _, err := Edit(in, Edits{Visibility: Visibility{Strip: matcher(t, false, name)}})
		if err == nil || !strings.Contains(err.Error(), "not stripping symbol "+name) {
			t.Errorf("strip %s: %v", name, err)
		}
	}
}

func TestWeakenInPlace(t *testing.T) {
	in := visibilityFixture()
	out, n, err := Edit(in, Edits{Visibility: Visibility{Weaken: matcher(t, false, "PyList_New", "malloc")}})
	if err != nil || n != 2 {
		t.Fatalf("Edit = %d, %v", n, err)
	}
	f, _ := elf.NewFile(bytes.NewReader(out))
	g, _ := elf.NewFile(bytes.NewReader(in))
	if f.Sections[symtabIndex].Offset != g.Sections[symtabIndex].Offset || len(out) != len(in) {
		t.Fatal("a binding change within the globals moved the symbol table")
	}
}

func TestVisibilityWithRenameAndWrap(t *testing.T) {
	in := visibilityFixture()
	// Matching uses input names; the wrapped definition's caller moves to
	// the added global __wrap_ symbol, which follows the reordered locals.
	out, _, err := Edit(in, Edits{
		Rename:     map[string]string{"XML_Parse": "ext_XML_Parse"},
		Wrap:       []string{"PyList_New"},
		Visibility: Visibility{Localize: matcher(t, false, "XML_Parse")},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := readBound(t, out)
	want := []string{".text:L", "helper:L", "$x:L", "unused:L", "ext_XML_Parse:L", "PyList_New:G", "_Py_hidden:G", "malloc:G", "absent:G", "tentative:G", "__wrap_PyList_New:G"}
	if !reflect.DeepEqual(got.symbols, want) {
		t.Fatalf("symbols = %q, want %q", got.symbols, want)
	}
	if want := []string{".text", "helper", "__wrap_PyList_New", "_Py_hidden", "ext_XML_Parse", "malloc", "tentative"}; !reflect.DeepEqual(got.relocs, want) {
		t.Fatalf("relocs = %q, want %q", got.relocs, want)
	}
}

func TestArchiveLocalizationKeepsMembersLinked(t *testing.T) {
	definer := testObject([]testSymbol{
		{"shared_helper", elf.STB_GLOBAL, elf.STT_FUNC, textSection, elf.STV_HIDDEN, false, false},
		{"api", elf.STB_GLOBAL, elf.STT_FUNC, textSection, 0, false, false},
	}, "")
	user := testObject([]testSymbol{
		{"shared_helper", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, false, false},
	}, "")
	in := testArchive(ar.Member{Name: "a.o", Data: definer}, ar.Member{Name: "b.o", Data: user})
	_, _, err := Edit(in, Edits{Visibility: Visibility{LocalizeHidden: true}})
	if err == nil || !strings.Contains(err.Error(), "b.o refers to shared_helper, which member a.o no longer exports") {
		t.Fatalf("Edit = %v", err)
	}
	// Without the cross-member reference the localized name leaves the index.
	out, _, err := Edit(testArchive(ar.Member{Name: "a.o", Data: definer}), Edits{Visibility: Visibility{LocalizeHidden: true}})
	if err != nil {
		t.Fatal(err)
	}
	members, _ := ar.Parse(out)
	if index := string(members[0].Data); strings.Contains(index, "shared_helper") || !strings.Contains(index, "api") {
		t.Fatalf("index = %q", index)
	}
}

func TestMatcherAndParseNames(t *testing.T) {
	m := matcher(t, true, "Py*", "_Py?", "!Py_Debug*")
	for name, want := range map[string]bool{"PyList_New": true, "_Pyx": true, "Py_DebugFlag": false, "XML": false} {
		if m.Match(name) != want {
			t.Errorf("Match(%s) != %v", name, want)
		}
	}
	if matcher(t, false, "Py*").Match("PyList") || !matcher(t, false, "Py*").Match("Py*") {
		t.Error("exact names matched as patterns")
	}
	if matcher(t, true, "!x").Match("y") {
		t.Error("a negated pattern alone matched")
	}
	if _, err := NewMatcher([]string{"[x"}, true); err == nil {
		t.Error("bad pattern accepted")
	}
	got, err := ParseNames(strings.NewReader("# api\n PyList_New \n\nPyDict_New # trailing\n"))
	if err != nil || !reflect.DeepEqual(got, []string{"PyList_New", "PyDict_New"}) {
		t.Fatalf("ParseNames = %q, %v", got, err)
	}
}
