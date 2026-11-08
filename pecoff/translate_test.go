package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/internal/ar"
)

func archiveFixture(members []ar.Member) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", m.Name+"/", 0, 0, 0, 0644, len(m.Data))
		b.Write(m.Data)
		if len(m.Data)%2 != 0 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes(), nil
}

func fixture(machine uint16) *object {
	return &object{machine: machine, sections: []section{{name: ".text", flags: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE | 0x500000, size: 16, data: make([]byte, 16)}}, symbols: []pe.COFFSymbol{{SectionNumber: 1, StorageClass: 2, Type: 0x20}}, names: []string{"example"}}
}
func encoded(t *testing.T, o *object) []byte {
	t.Helper()
	b, err := o.encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestImportNamespaceAndDebugRemoval(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.sections = append(o.sections, section{name: ".debug_info", flags: pe.IMAGE_SCN_MEM_DISCARDABLE | pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: 12, data: []byte("PRIVATE_PATH")})
	o.addSymbol("debug", 2, 0)
	o.addSymbol("__imp_GetCurrentProcessId", 0, 0)
	o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: 2, Type: 4}}
	input := encoded(t, o)
	p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Imports) != 1 || p.Imports[0].DLL != "kernel32.dll" || bytes.Contains(p.Objects[0], []byte("PRIVATE_PATH")) {
		t.Fatal("import/debug contract failed")
	}
	got, err := parse(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.names[got.sections[0].relocs[0].SymbolTableIndex] != p.Imports[0].Local || got.names[0] != p.Exports[0] {
		t.Fatal("namespace/remapped relocation lost")
	}
	if !bytes.Equal(input, encoded(t, o)) {
		t.Fatal("original input mutated")
	}
}

func TestUnsupportedRuntimeBoundaries(t *testing.T) {
	for _, kind := range []string{"tls-relocation", "unknown-crt-section", "alignment", "relocation", "unknown-import", "bad-map", "bad-export", "data-export", "data-import", "ctor-priority"} {
		t.Run(kind, func(t *testing.T) {
			o := fixture(pe.IMAGE_FILE_MACHINE_ARM64)
			opts := Options{Symbols: []string{"example"}, StripDebug: true}
			switch kind {
			case "tls-relocation":
				o.sections = append(o.sections, section{name: ".tls$", size: 8, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE, data: make([]byte, 8), relocs: []pe.Reloc{{Type: 14}}})
			case "unknown-crt-section":
				o.sections = append(o.sections, section{name: ".CRT$XY", size: 8, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, data: make([]byte, 8)})
			case "alignment":
				o.sections[0].flags = o.sections[0].flags&^0xf00000 | 0x800000
			case "relocation":
				o.sections[0].relocs = []pe.Reloc{{Type: 8}}
			case "unknown-import":
				o.addSymbol("unknown_crt_function", 0, 0)
				o.sections[0].relocs = []pe.Reloc{{Type: 4, SymbolTableIndex: 1}}
			case "bad-map":
				opts.Imports = map[string]string{"GetValue": "../evil.dll"}
			case "bad-export":
				opts.Symbols = []string{"missing"}
			case "data-export":
				o.symbols[0].Type = 0
			case "data-import":
				o.addSymbol("CustomFunction", 0, 0)
				opts.Imports = map[string]string{"CustomFunction": "system.dll"}
				o.sections[0].relocs = []pe.Reloc{{Type: 14, SymbolTableIndex: 1}}
			case "c-initializer", "ctor-priority":
				name := ".CRT$XIU"
				if kind == "ctor-priority" {
					name = ".ctors.invalid"
				}
				o.sections = append(o.sections, section{name: name, size: 8, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, data: make([]byte, 8)})
			}
			if _, err := Translate(encoded(t, o), opts); err == nil {
				t.Fatal("unsupported input accepted")
			}
		})
	}
}

func TestMSVCSectionsAndAddends(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.sections = append(o.sections,
		section{name: ".pdata", size: 12, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, data: make([]byte, 12), relocs: []pe.Reloc{{Type: 3}, {Type: 3, VirtualAddress: 4}, {Type: 3, VirtualAddress: 8}}},
		section{name: ".pdata", size: 12, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, data: make([]byte, 12), relocs: []pe.Reloc{{Type: 3}, {Type: 3, VirtualAddress: 4}, {Type: 3, VirtualAddress: 8}}},
		section{name: ".rdata", size: 8, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_LNK_COMDAT | 0x600000, data: make([]byte, 8)},
		section{name: ".rdata", size: 8, flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_LNK_COMDAT, data: make([]byte, 8)},
		section{name: ".chks64", size: 7, flags: 0x800, data: []byte("PRIVATE")})
	o.addSymbol("?private@@YAHXZ", 3, 0)
	o.addSymbol("__real@value", 4, 0)
	o.addSymbol("other_data", 5, 0)
	comdatMetadata(o, 3, 2, -1)
	comdatMetadata(o, 4, 2, -1)
	o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: 2, Type: 9}}
	binary.LittleEndian.PutUint32(o.sections[0].data[4:], 9)
	p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Unwind) != 1 || p.Unwind[0].Count != 2 || len(got.sections[1].relocs) != 6 || got.sections[1].relocs[3].VirtualAddress != 12 || got.symbols[1].SectionNumber != 2 || got.symbols[1].Value != 12 {
		t.Fatal("duplicate SEH fragments or their symbols/relocations were lost")
	}
	if got.sections[0].relocs[0].Type != 4 || binary.LittleEndian.Uint32(got.sections[0].data[4:]) != 4 {
		t.Fatal("REL32_5 implicit addend changed incorrectly")
	}
	if got.sections[3].size != 32 || got.sections[3].flags&pe.IMAGE_SCN_LNK_COMDAT != 0 || got.sections[3].name == got.sections[4].name {
		t.Fatal("data alignment/section identities lost")
	}
	if bytes.Contains(p.Objects[0], []byte("PRIVATE")) || !strings.HasPrefix(got.names[1], p.Namespace+"sym_") {
		t.Fatal("metadata not stripped or decorated private symbol not isolated")
	}
}

func TestArchiveSelectionAndDuplicateDefinitions(t *testing.T) {
	root := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	helper := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	helper.names[0] = "helper"
	root.addSymbol("helper", 0, 0)
	root.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: 1, Type: 4}}
	unused := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	unused.names[0] = "unused"
	unused.sections = append(unused.sections, section{name: ".tls", size: 8, data: make([]byte, 8)})
	input, err := archiveFixture([]ar.Member{{Name: "root.obj", Data: encoded(t, root)}, {Name: "helper.obj", Data: encoded(t, helper)}, {Name: "unused.obj", Data: encoded(t, unused)}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil || len(p.Objects) != 2 {
		t.Fatalf("selected dependency closure: %v %+v", err, p)
	}
	helper.addSymbol("example", 1, 0)
	input, err = archiveFixture([]ar.Member{{Name: "root.obj", Data: encoded(t, root)}, {Name: "helper.obj", Data: encoded(t, helper)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(input, Options{Symbols: []string{"example"}}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("ambiguous selected definitions accepted: %v", err)
	}
}

func TestUnwindTablesRetainImageRelativeRecords(t *testing.T) {
	for _, m := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		o := fixture(m)
		size, typ := uint32(12), uint16(3)
		if m == pe.IMAGE_FILE_MACHINE_ARM64 {
			size, typ = 8, 2
		}
		relocs := []pe.Reloc{{Type: typ}}
		if m == pe.IMAGE_FILE_MACHINE_AMD64 {
			relocs = append(relocs, pe.Reloc{Type: typ, VirtualAddress: 4}, pe.Reloc{Type: typ, VirtualAddress: 8})
		}
		o.sections = append(o.sections, section{name: ".pdata", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: size, data: make([]byte, size), relocs: relocs})
		p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Unwind) != 1 || p.Unwind[0].Count != 1 {
			t.Fatal("native function table lost")
		}
		got, err := parse(p.Objects[0])
		if err != nil {
			t.Fatal(err)
		}
		wantName := ".pdata"
		if m == pe.IMAGE_FILE_MACHINE_ARM64 {
			wantName = ".bao.pd"
		}
		if got.sections[1].name != wantName || got.sections[1].relocs[0].Type != typ {
			t.Fatal("image-relative unwind relocation changed")
		}
	}
}
