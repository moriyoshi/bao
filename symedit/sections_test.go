package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func sectionFixture() []byte {
	return testObject([]testSymbol{
		{".text", elf.STB_LOCAL, elf.STT_SECTION, textSection, 0, false, false},
		{"helper", elf.STB_LOCAL, elf.STT_FUNC, textSection, 0, false, false},
		{"foo", elf.STB_GLOBAL, elf.STT_FUNC, textSection, 0, false, true},
		{"bar", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF, 0, false, false},
		{"shared", elf.STB_GLOBAL, elf.STT_OBJECT, elf.SHN_COMMON, 0, false, false},
	}, "foo")
}

// layout reads back section names, each relocation section's target and
// symbol table link, the group's members and signature, and the symbols with
// the names of their sections.
func layout(t *testing.T, data []byte) (sections []string, rela map[string]string, group []string, symbols []string) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	rela = map[string]string{}
	for _, s := range f.Sections {
		sections = append(sections, s.Name)
		switch s.Type {
		case elf.SHT_RELA:
			rela[s.Name] = f.Sections[s.Info].Name + "/" + f.Sections[s.Link].Name
		case elf.SHT_GROUP:
			b, _ := s.Data()
			for off := 4; off < len(b); off += 4 {
				group = append(group, f.Sections[binary.LittleEndian.Uint32(b[off:])].Name)
			}
		}
	}
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range syms {
		where := "UND"
		switch {
		case s.Section == elf.SHN_COMMON:
			where = "COM"
		case s.Section == elf.SHN_ABS:
			where = "ABS"
		case s.Section > 0 && int(s.Section) < len(f.Sections):
			where = f.Sections[s.Section].Name
		}
		symbols = append(symbols, s.Name+"@"+where)
	}
	return
}

func TestRemoveSectionRenumbers(t *testing.T) {
	in := sectionFixture()
	out, n, err := Edit(in, Edits{RemoveSection: matcher(t, false, ".debug_info")})
	if err != nil {
		t.Fatal(err)
	}
	// .rela.debug_info goes with its target, which also releases foo.
	if n != 2 {
		t.Fatalf("edited %d, want 2", n)
	}
	sections, rela, members, symbols := layout(t, out)
	if want := []string{"", ".text", ".rela.text", ".symtab", ".symtab_shndx", ".strtab", ".group", ".llvm_addrsig"}; !reflect.DeepEqual(sections, want) {
		t.Fatalf("sections = %q, want %q", sections, want)
	}
	if rela[".rela.text"] != ".text/.symtab" || !reflect.DeepEqual(members, []string{".text"}) {
		t.Fatalf("rela = %v, group = %q", rela, members)
	}
	if want := []string{".text@.text", "helper@.text", "foo@.text", "bar@UND", "shared@COM"}; !reflect.DeepEqual(symbols, want) {
		t.Fatalf("symbols = %q, want %q", symbols, want)
	}
	f, _ := elf.NewFile(bytes.NewReader(out))
	syms, _ := f.Symbols()
	group := f.Section(".group")
	_, _, relocs := view(t, out)
	if syms[group.Info-1].Name != "foo" || !reflect.DeepEqual(relocs[".rela.text"], []string{".text", "helper", "foo", "bar", "shared"}) {
		t.Fatalf("signature %q, relocs %q", syms[group.Info-1].Name, relocs[".rela.text"])
	}
	// Every local precedes sh_info.
	for i, s := range syms {
		if (elf.ST_BIND(s.Info) == elf.STB_LOCAL) != (uint32(i+1) < f.Section(".symtab").Info) {
			t.Fatalf("symbol %s is on the wrong side of sh_info", s.Name)
		}
	}
}

func TestRemoveSectionRefusals(t *testing.T) {
	in := sectionFixture()
	for _, tc := range []struct {
		e    Edits
		want string
	}{
		// Debug data still describes foo, which .text defines.
		{Edits{RemoveSection: matcher(t, false, ".text")}, "a kept relocation or section group names foo"},
		{Edits{RemoveSection: matcher(t, false, ".symtab")}, "which the symbol table needs"},
		{Edits{RemoveSection: matcher(t, false, ".strtab")}, "which the symbol table needs"},
		{Edits{AddSymbols: []AddedSymbol{{Name: "x", Section: ".debug_info"}}, RemoveSection: matcher(t, false, ".debug_info")}, "missing ELF section .debug_info"},
		{Edits{AddSymbols: []AddedSymbol{{Name: "foo", Section: ".text"}}}, "already defined"},
	} {
		if _, _, err := Edit(in, tc.e); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.e, err, tc.want)
		}
	}
	// With its debug data, .text and the group it alone fills can go.
	out, _, err := Edit(in, Edits{RemoveSection: matcher(t, true, ".text", ".debug*")})
	if err != nil {
		t.Fatal(err)
	}
	sections, _, _, symbols := layout(t, out)
	if want := []string{"", ".symtab", ".symtab_shndx", ".strtab", ".llvm_addrsig"}; !reflect.DeepEqual(sections, want) {
		t.Fatalf("sections = %q, want %q", sections, want)
	}
	if want := []string{"bar@UND", "shared@COM"}; !reflect.DeepEqual(symbols, want) {
		t.Fatalf("symbols = %q, want %q", symbols, want)
	}
}

func TestOnlySection(t *testing.T) {
	out, _, err := Edit(sectionFixture(), Edits{OnlySection: matcher(t, false, ".text")})
	if err != nil {
		t.Fatal(err)
	}
	// The tables, .text's relocations and its group stay.
	sections, rela, group, _ := layout(t, out)
	if want := []string{"", ".text", ".rela.text", ".symtab", ".symtab_shndx", ".strtab", ".group"}; !reflect.DeepEqual(sections, want) {
		t.Fatalf("sections = %q, want %q", sections, want)
	}
	if rela[".rela.text"] != ".text/.symtab" || !reflect.DeepEqual(group, []string{".text"}) {
		t.Fatalf("rela = %v, group = %q", rela, group)
	}
}

func TestAddSymbol(t *testing.T) {
	var added []AddedSymbol
	for _, spec := range []string{"marker=.text:0x8,function,hidden", "local_marker=.text:4,local", "abs_sym=0x1234,weak,object"} {
		a, err := ParseAddSymbol(spec)
		if err != nil {
			t.Fatal(err)
		}
		added = append(added, a)
	}
	out, n, err := Edit(sectionFixture(), Edits{AddSymbols: added, RemoveSection: matcher(t, false, ".debug_info")})
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("edited %d, want 5", n)
	}
	_, _, _, symbols := layout(t, out)
	// The local one joins the locals, before sh_info.
	if want := []string{".text@.text", "helper@.text", "local_marker@.text", "foo@.text", "bar@UND", "shared@COM", "marker@.text", "abs_sym@ABS"}; !reflect.DeepEqual(symbols, want) {
		t.Fatalf("symbols = %q, want %q", symbols, want)
	}
	f, _ := elf.NewFile(bytes.NewReader(out))
	syms, _ := f.Symbols()
	m, a := syms[6], syms[7]
	if m.Value != 8 || elf.ST_TYPE(m.Info) != elf.STT_FUNC || elf.ST_VISIBILITY(m.Other) != elf.STV_HIDDEN || elf.ST_BIND(m.Info) != elf.STB_GLOBAL {
		t.Fatalf("marker = %+v", m)
	}
	if a.Value != 0x1234 || elf.ST_BIND(a.Info) != elf.STB_WEAK || elf.ST_TYPE(a.Info) != elf.STT_OBJECT {
		t.Fatalf("abs_sym = %+v", a)
	}
	if f.Section(".symtab").Info != 4 {
		t.Fatalf("sh_info = %d, want 4", f.Section(".symtab").Info)
	}
}

func TestParseAddSymbol(t *testing.T) {
	a, err := ParseAddSymbol("x=.data.rel.ro:16")
	if err != nil || a != (AddedSymbol{Name: "x", Section: ".data.rel.ro", Value: 16, Bind: elf.STB_GLOBAL, Type: elf.STT_NOTYPE}) {
		t.Fatalf("%+v %v", a, err)
	}
	if a, err := ParseAddSymbol("y=__DATA,__data:8,weak"); err != nil || a.Section != "__DATA,__data" || a.Value != 8 || a.Bind != elf.STB_WEAK {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []string{"x", "=1", "x=.text:", "x=:1", "x=1,bogus", "x=.text:zz"} {
		if _, err := ParseAddSymbol(bad); err == nil {
			t.Errorf("ParseAddSymbol(%q) succeeded", bad)
		}
	}
}

func addSymbols(t *testing.T, specs ...string) []AddedSymbol {
	t.Helper()
	var out []AddedSymbol
	for _, spec := range specs {
		a, err := ParseAddSymbol(spec)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func TestAddSymbolAtSymbol(t *testing.T) {
	if a, err := ParseAddSymbol("alias=@foo:8,function"); err != nil || a.Symbol != "foo" || a.Section != "" || a.Value != 8 || a.Type != elf.STT_FUNC {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := ParseAddSymbol("alias=@:8"); err == nil {
		t.Fatal("empty target accepted")
	}
	out, _, err := Edit(sectionFixture(), Edits{AddSymbols: addSymbols(t, "foo_alias=@foo:8,function", "helper_alias=@helper:4,local")})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := elf.NewFile(bytes.NewReader(out))
	syms, _ := f.Symbols()
	got := map[string]elf.Symbol{}
	for _, s := range syms {
		got[s.Name] = s
	}
	if s := got["foo_alias"]; s.Section != got["foo"].Section || s.Value != 8 || elf.ST_TYPE(s.Info) != elf.STT_FUNC || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
		t.Fatalf("foo_alias = %+v", s)
	}
	// A local target is found when no global has the name.
	if s := got["helper_alias"]; s.Section != got["helper"].Section || s.Value != 4 || elf.ST_BIND(s.Info) != elf.STB_LOCAL {
		t.Fatalf("helper_alias = %+v", s)
	}
	dup := testObject([]testSymbol{
		{".text", elf.STB_LOCAL, elf.STT_SECTION, textSection, 0, false, false},
		{"dup", elf.STB_LOCAL, elf.STT_FUNC, textSection, 0, false, false},
		{"dup", elf.STB_LOCAL, elf.STT_FUNC, textSection, 0, false, false},
	}, "")
	for spec, want := range map[string]string{
		"x=@bar:0":    "which the object does not define",
		"x=@shared:0": "which the object does not define",
		"x=@nosuch:0": "which the object does not define",
	} {
		if _, _, err := Edit(sectionFixture(), Edits{AddSymbols: addSymbols(t, spec)}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", spec, err)
		}
	}
	if _, _, err := Edit(dup, Edits{AddSymbols: addSymbols(t, "x=@dup:0")}); err == nil || !strings.Contains(err.Error(), "names 2 definitions") {
		t.Errorf("ambiguous target: %v", err)
	}
}
