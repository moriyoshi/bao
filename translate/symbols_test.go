package translate

import (
	"bytes"
	"debug/macho"
	"testing"
)

func TestCoalesceIdenticalTextAliasesPreservesReferences(t *testing.T) {
	o := fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, make([]byte, 32), []macho.Reloc{{Addr: 4, Type: 2, Len: 2, Extern: true, Pcrel: true, Value: 1}}},
		{"__data", "__DATA", 0, make([]byte, 8), []macho.Reloc{{Type: 0, Len: 3, Extern: true, Value: 2}}},
	}, []macho.Symbol{
		{Name: "_c_api", Type: 0xf, Sect: 1},
		{Name: "__RNv_alias", Type: 0xf, Sect: 1},
		{Name: "ltmp_alias", Type: 0xe, Sect: 1},
		{Name: "__RNv_distinct", Type: 0xf, Sect: 1, Value: 16},
	})
	m, err := readImage(o)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), m.sections[0].data...)
	n, err := m.coalesceTextAliases(nil)
	if err != nil || n != 2 {
		t.Fatalf("coalesce: %d %v", n, err)
	}
	if len(m.symbols) != 2 || m.symbols[0].Name != "_c_api" || m.symbols[1].Value != 16 {
		t.Fatalf("distinct function/C API changed: %+v", m.symbols)
	}
	for _, section := range m.sections {
		for _, r := range section.relocs {
			if m.symbols[r.Value].Name != "_c_api" || m.symbols[r.Value].Value != 0 {
				t.Fatal("alias reference changed its target address")
			}
		}
	}
	if !bytes.Equal(before, m.sections[0].data) {
		t.Fatal("coalescing changed native code")
	}
}

func TestKeepRequestedMangledAPIAndBoundarySymbols(t *testing.T) {
	o := fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, make([]byte, 32), nil},
		{"_CTOR0_ISIZE_FN", "__DATA", 0, make([]byte, 32), nil},
	}, []macho.Symbol{
		{Name: "__RNv_keep", Type: 0xf, Sect: 1},
		{Name: "__RNv_other", Type: 0xf, Sect: 1},
		{Name: "section$start$__DATA$_CTOR0_ISIZE_FN", Type: 1},
		{Name: "section$end$__DATA$_CTOR0_ISIZE_FN", Type: 1},
	})
	m, err := readImage(o)
	if err != nil {
		t.Fatal(err)
	}
	if n := m.synthesizeBoundaries(); n != 2 {
		t.Fatalf("boundaries=%d", n)
	}
	if m.symbols[2].Sect != 2 || m.symbols[2].Value != 32 || m.symbols[3].Value != 64 {
		t.Fatal("incorrect section bounds")
	}
	if _, err := m.coalesceTextAliases(map[string]bool{"__RNv_keep": true}); err != nil {
		t.Fatal(err)
	}
	if m.symbols[0].Name != "__RNv_keep" {
		t.Fatal("explicitly kept native entry was removed")
	}
}
