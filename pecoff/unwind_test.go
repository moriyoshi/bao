package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

func TestColdFunctionUnwindOrderingAndRecordReferences(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.sections = append(o.sections, section{name: ".text.unlikely", flags: o.sections[0].flags, size: 16, data: make([]byte, 16)})
	o.addSymbol("cold", 2, 0)
	o.symbols[1].Type = 0x20
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[4:], 16)
	binary.LittleEndian.PutUint32(data[16:], 16)
	relocs := []pe.Reloc{{Type: 3, SymbolTableIndex: 1}, {Type: 3, SymbolTableIndex: 1, VirtualAddress: 4}, {Type: 3, SymbolTableIndex: 2, VirtualAddress: 8}, {Type: 3, VirtualAddress: 12}, {Type: 3, VirtualAddress: 16}, {Type: 3, SymbolTableIndex: 2, VirtualAddress: 20}}
	o.sections = append(o.sections, section{name: ".pdata", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: 24, data: data, relocs: relocs})
	o.sections = append(o.sections, section{name: ".xdata", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: 4, data: []byte{1, 0, 0, 0}})
	o.addSymbol("unwind", 4, 0)
	o.addSymbol("cold_record", 3, 0)
	o.addSymbol(".pdata", 3, 0)
	o.symbols[4].StorageClass = 3
	ref := make([]byte, 8)
	binary.LittleEndian.PutUint32(ref, 4)
	binary.LittleEndian.PutUint32(ref[4:], 12)
	o.sections = append(o.sections, section{name: ".rdata", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: 8, data: ref, relocs: []pe.Reloc{{Type: 3, SymbolTableIndex: 3}, {Type: 3, SymbolTableIndex: 4, VirtualAddress: 4}}})
	p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.names[got.sections[2].relocs[0].SymbolTableIndex] != p.Namespace+"example" || got.names[got.sections[2].relocs[3].SymbolTableIndex] != p.Namespace+"cold" {
		t.Fatal("GCC cold record still precedes its hot section")
	}
	if got.symbols[3].Value != 12 || got.symbols[4].Value != 0 || binary.LittleEndian.Uint32(got.sections[4].data) != 4 || binary.LittleEndian.Uint32(got.sections[4].data[4:]) != 0 {
		t.Fatal("record label, section base or record-reference addend changed incorrectly")
	}
	if len(p.UnwindRoots) != 1 || p.UnwindRoots[0].Count != 3 {
		t.Fatal("native SEH targets are not rooted")
	}
	roots := got.sections[len(got.sections)-1]
	if roots.name != ".bao.uwr" || len(roots.relocs) != 3 {
		t.Fatal("unwind retention is not ordinary native data")
	}
	for _, r := range roots.relocs {
		if r.Type != 1 {
			t.Fatal("native unwind root is not a strong absolute pointer")
		}
	}
	// Duplicate relocation sites leave another column without a relocation.
	o.sections[2].relocs[1].VirtualAddress = 0
	if _, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}}); err == nil {
		t.Fatal("overlapping unwind relocations accepted")
	}
}
