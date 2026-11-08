package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/internal/ar"
)

func comdatMetadata(o *object, si int, selection byte, parent int) {
	var raw [18]byte
	binary.LittleEndian.PutUint32(raw[:], o.sections[si].size)
	binary.LittleEndian.PutUint16(raw[12:], uint16(parent+1))
	raw[14] = selection
	var aux pe.COFFSymbol
	binary.Read(bytes.NewReader(raw[:]), binary.LittleEndian, &aux)
	o.symbols = append(o.symbols, pe.COFFSymbol{SectionNumber: int16(si + 1), StorageClass: 3, NumberOfAuxSymbols: 1}, aux)
	o.names = append(o.names, o.sections[si].name, "")
}

func comdatObject(name string, policy byte, size uint32) *object {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.names[0] = name
	o.sections = append(o.sections, section{name: ".text$shared", size: size, data: make([]byte, size), flags: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_LNK_COMDAT | 0x500000})
	o.addSymbol("shared", 2, 0)
	o.symbols[1].Type = 0x20
	comdatMetadata(o, 1, policy, -1)
	return o
}

func TestCOMDATSelection(t *testing.T) {
	for _, policy := range []byte{1, 2, 3, 4, 6, 7} {
		t.Run(string(rune('0'+policy)), func(t *testing.T) {
			a, b := comdatObject("a", policy, 16), comdatObject("b", policy, 16)
			if policy == 6 {
				b.sections[1].size = 32
				b.sections[1].data = make([]byte, 32)
			}
			if policy == 7 {
				a.timestamp = 1
				b.timestamp = 2
			}
			objects := []*object{a, b}
			err := selectCOMDAT(objects, map[int]bool{0: true, 1: true}, map[string]int{}, "test_")
			if policy == 1 {
				if err == nil {
					t.Fatal("duplicate NODUPLICATES accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			loser := 1
			if policy == 6 || policy == 7 {
				loser = 0
			}
			if objects[loser].sections[1].size != 0 || objects[1-loser].sections[1].size == 0 {
				t.Fatal("incorrect winner")
			}
		})
	}
}

func TestCOMDATMismatchControls(t *testing.T) {
	for _, kind := range []string{"size", "bytes", "relocation", "policy", "cycle", "parent", "missing"} {
		t.Run(kind, func(t *testing.T) {
			a, b := comdatObject("a", 4, 16), comdatObject("b", 4, 16)
			switch kind {
			case "size":
				a, b = comdatObject("a", 3, 16), comdatObject("b", 3, 32)
			case "bytes":
				b.sections[1].data[0] = 1
			case "relocation":
				a.addSymbol("left", 0, 0)
				b.addSymbol("right", 0, 0)
				a.sections[1].relocs = []pe.Reloc{{SymbolTableIndex: 4, Type: 4}}
				b.sections[1].relocs = []pe.Reloc{{SymbolTableIndex: 4, Type: 4}}
			case "policy":
				b = comdatObject("b", 2, 16)
			case "cycle", "parent":
				a.symbols = a.symbols[:2]
				a.names = a.names[:2]
				parent := 1
				if kind == "parent" {
					parent = 0
				}
				comdatMetadata(a, 1, 5, parent)
			case "missing":
				a.symbols = a.symbols[:2]
				a.names = a.names[:2]
			}
			if err := selectCOMDAT([]*object{a, b}, map[int]bool{0: true, 1: true}, map[string]int{}, "test_"); err == nil {
				t.Fatal("invalid COMDAT accepted")
			}
		})
	}
}

func TestCOMDATAssociationsAndLocalReferences(t *testing.T) {
	a, b := comdatObject("a", 2, 16), comdatObject("b", 2, 16)
	for _, o := range []*object{a, b} {
		for si := 2; si < 4; si++ {
			o.sections = append(o.sections, section{name: ".metadata", size: 8, data: make([]byte, 8), flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_LNK_COMDAT})
			comdatMetadata(o, si, 5, si-1)
		}
	}
	b.addSymbol("local", 4, 4)
	b.symbols[len(b.symbols)-1].StorageClass = 3
	b.sections[0].relocs = []pe.Reloc{{SymbolTableIndex: uint32(len(b.symbols) - 1), Type: 1}}
	defs := map[string]int{}
	if err := selectCOMDAT([]*object{a, b}, map[int]bool{0: true, 1: true}, defs, "test_"); err != nil {
		t.Fatal(err)
	}
	for _, si := range []int{1, 2, 3} {
		if b.sections[si].size != 0 {
			t.Fatal("associated loser retained")
		}
	}
	s := b.symbols[b.sections[0].relocs[0].SymbolTableIndex]
	name := b.names[b.sections[0].relocs[0].SymbolTableIndex]
	if s.SectionNumber != 0 || s.StorageClass != 2 || !strings.HasPrefix(name, "test_comdat_") || defs[name] != 0 {
		t.Fatal("local target was not redirected")
	}
	if a.names[len(a.names)-1] != name || a.symbols[len(a.symbols)-1].SectionNumber != 4 || a.symbols[len(a.symbols)-1].Value != 4 {
		t.Fatal("anchor lost offset or association")
	}
}

func TestCOMDATArchiveClosure(t *testing.T) {
	a, b := comdatObject("a", 2, 16), comdatObject("b", 2, 16)
	b.addSymbol("unavailable_in_discarded_copy", 0, 0)
	b.sections[1].relocs = []pe.Reloc{{SymbolTableIndex: 4, Type: 4}}
	input, _ := archiveFixture([]ar.Member{{Name: "a.obj", Data: encoded(t, a)}, {Name: "b.obj", Data: encoded(t, b)}})
	if _, err := Translate(input, Options{Symbols: []string{"a", "b"}, StripDebug: true}); err != nil {
		t.Fatal(err)
	}
	// An unextracted NODUPLICATES definition must not cause a duplicate error.
	a, b = comdatObject("a", 1, 16), comdatObject("b", 1, 16)
	input, _ = archiveFixture([]ar.Member{{Name: "a.obj", Data: encoded(t, a)}, {Name: "b.obj", Data: encoded(t, b)}})
	if _, err := Translate(input, Options{Symbols: []string{"a"}, StripDebug: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(input, Options{Symbols: []string{"a", "b"}, StripDebug: true}); err == nil {
		t.Fatal("selected NODUPLICATES duplicate accepted")
	}
}

func TestCOMDATExactMatchSymbolIndices(t *testing.T) {
	a, b := comdatObject("a", 4, 16), comdatObject("b", 4, 16)
	a.addSymbol("dependency", 0, 0)
	b.addSymbol("unused", 0, 0)
	b.addSymbol("dependency", 0, 0)
	a.sections[1].relocs = []pe.Reloc{{Type: 4, SymbolTableIndex: 4}}
	b.sections[1].relocs = []pe.Reloc{{Type: 4, SymbolTableIndex: 5}}
	if err := selectCOMDAT([]*object{a, b}, map[int]bool{0: true, 1: true}, map[string]int{}, "test_"); err != nil {
		t.Fatal(err)
	}
}

func TestCOMDATWeakAliasIndexCompaction(t *testing.T) {
	a, b := comdatObject("a", 2, 16), comdatObject("b", 2, 16)
	weak := addWeak(b, "optional", 1, 3)
	b.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: weak, Type: 4}}
	defs := map[string]int{}
	selected := map[int]bool{0: true, 1: true}
	if err := selectCOMDAT([]*object{a, b}, selected, defs, "test_"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(b.symbols); {
		s := b.symbols[i]
		if s.StorageClass == 2 && s.SectionNumber == 0 && s.NumberOfAuxSymbols != 0 {
			t.Fatal("redirected external retains section auxiliary data")
		}
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	if err := b.resolveWeak(defs, selected); err != nil {
		t.Fatal(err)
	}
	i := b.sections[0].relocs[0].SymbolTableIndex
	if b.names[i] != "shared" || b.symbols[i].SectionNumber != 0 {
		t.Fatal("COMDAT compaction lost weak target")
	}
}

func TestWindowsScopedLocalLabelIdentity(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_ARM64)
	o.addSymbol("$LN15", 1, 4)
	o.symbols[1].StorageClass = 6
	o.addSymbol("$LN15", 1, 8)
	o.symbols[2].StorageClass = 6
	p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.names[1] == got.names[2] || got.symbols[1].Value != 4 || got.symbols[2].Value != 8 {
		t.Fatal("function-scoped local labels collapsed")
	}
}

func TestCOMDATUnwindSelection(t *testing.T) {
	a, b := comdatObject("a", 2, 16), comdatObject("b", 2, 16)
	for _, o := range []*object{a, b} {
		o.sections = append(o.sections, section{name: ".xdata", size: 4, data: []byte{1, 0, 0, 0}, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_LNK_COMDAT})
		o.addSymbol("unwind", 3, 0)
		o.symbols[4].StorageClass = 3
		comdatMetadata(o, 2, 5, 1)
		data := make([]byte, 12)
		binary.LittleEndian.PutUint32(data[4:], 16)
		o.sections = append(o.sections, section{name: ".pdata", size: 12, data: data, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_LNK_COMDAT, relocs: []pe.Reloc{{Type: 3, SymbolTableIndex: 1}, {Type: 3, SymbolTableIndex: 1, VirtualAddress: 4}, {Type: 3, SymbolTableIndex: 4, VirtualAddress: 8}}})
		comdatMetadata(o, 3, 5, 1)
	}
	input, _ := archiveFixture([]ar.Member{{Name: "a.obj", Data: encoded(t, a)}, {Name: "b.obj", Data: encoded(t, b)}})
	p, err := Translate(input, Options{Symbols: []string{"a", "b"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Objects) != 2 || len(p.Unwind) != 1 || p.Unwind[0].Count != 1 || len(p.UnwindRoots) != 1 {
		t.Fatal("losing COMDAT unwind records survived aggregation")
	}
}
