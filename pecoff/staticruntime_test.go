package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/internal/ar"
)

func TestArchiveWeakImplementationProvider(t *testing.T) {
	root, provider := fixture(pe.IMAGE_FILE_MACHINE_AMD64), fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	provider.names[0] = "implementation"
	addWeak(provider, "api", 0, 3)
	root.addSymbol("api", 0, 0)
	root.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: 1, Type: 4}}
	input, _ := archiveFixture([]ar.Member{{Name: "root.obj", Data: encoded(t, root)}, {Name: "provider.obj", Data: encoded(t, provider)}})
	p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Objects) != 2 || len(p.Imports) != 0 {
		t.Fatal("weak implementation did not satisfy the archive reference")
	}
	got, err := parse(p.Objects[1])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i, s := range got.symbols {
		if got.names[i] == p.Namespace+"api" && s.SectionNumber > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("weak library API has no local definition")
	}
}

func TestLocalImportCellsDoNotExtractUnrelatedProviders(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		root, provider, bad := fixture(machine), fixture(machine), fixture(machine)
		provider.names[0] = "api"
		bad.names[0] = "unused"
		root.addSymbol("__imp_api", 0, 0)
		root.addSymbol("__imp_unused", 0, 0)
		typ := uint16(1)
		if machine == pe.IMAGE_FILE_MACHINE_ARM64 {
			typ = 14
		}
		root.sections[0].relocs = []pe.Reloc{{SymbolTableIndex: 1, Type: typ}}
		bad.addSymbol("unavailable_library_dependency", 0, 0)
		bad.sections[0].relocs = []pe.Reloc{{Type: typ, SymbolTableIndex: 1}}
		input, _ := archiveFixture([]ar.Member{{Name: "root.obj", Data: encoded(t, root)}, {Name: "api.obj", Data: encoded(t, provider)}, {Name: "unused.obj", Data: encoded(t, bad)}})
		p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Objects) != 3 || len(p.Imports) != 0 {
			t.Fatal("local import cell extracted an unrelated member")
		}
		cell, err := parse(p.Objects[2])
		if err != nil {
			t.Fatal(err)
		}
		if cell.sections[0].relocs[0].Type != typ || cell.names[cell.sections[0].relocs[0].SymbolTableIndex] != p.Namespace+"api" {
			t.Fatal("local import pointer lost its definition")
		}
	}
}

func TestGNUCOFFInitializerPriorities(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	for _, name := range []string{".ctors.65000", ".CRT$XCU", ".ctors.65534", ".dtors.65534", ".dtors.65000"} {
		o.sections = append(o.sections, section{name: name, size: 8, data: make([]byte, 8), flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, relocs: []pe.Reloc{{Type: 1}}})
	}
	p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Constructors) != 3 || p.Constructors[0].Order != ".ctors.65534" || p.Constructors[1].Order != ".ctors.65000" || len(p.Terminators) != 2 || p.Terminators[0].Order != ".dtors.65000" {
		t.Fatal("GNU constructor/destructor priorities lost")
	}
	for _, name := range []string{".ctors.invalid", ".ctors.65536", ".dtors.-1"} {
		if _, err := gnuInitializerPriority(name); err == nil {
			t.Fatal("invalid priority accepted", name)
		}
	}
}

func tlsAnchorFixture() *object {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.sections = append(o.sections, section{name: ".rdata", size: 16, data: make([]byte, 16), flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, relocs: []pe.Reloc{{VirtualAddress: 8, Type: 1, SymbolTableIndex: 2}}})
	o.addSymbol("_include_tls_used", 2, 8)
	o.symbols[1].StorageClass = 3
	o.addSymbol("_tls_used", 0, 0)
	return o
}
func TestTLSDirectoryLinkerAnchor(t *testing.T) {
	o := tlsAnchorFixture()
	if _, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"referenced", "section-reference", "directory-read", "writable", "bad-relocation"} {
		t.Run(kind, func(t *testing.T) {
			o := tlsAnchorFixture()
			switch kind {
			case "referenced":
				o.sections[0].relocs = []pe.Reloc{{Type: 1, SymbolTableIndex: 1}}
			case "section-reference":
				o.addSymbol(".rdata", 2, 0)
				o.symbols[3].StorageClass = 3
				o.sections[0].relocs = []pe.Reloc{{Type: 1, SymbolTableIndex: 3}}
				binary.LittleEndian.PutUint64(o.sections[0].data, 8)
			case "directory-read":
				o.sections[0].relocs = []pe.Reloc{{Type: 1, SymbolTableIndex: 2}}
			case "writable":
				o.sections[1].flags |= pe.IMAGE_SCN_MEM_WRITE
			case "bad-relocation":
				o.sections[1].relocs[0].Type = 4
			}
			if _, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true}); err == nil {
				t.Fatal("runtime TLS-directory access was silently replaced")
			}
		})
	}
}

func TestWindowsSystemCRTAndExportAliases(t *testing.T) {
	for _, crt := range []string{"ucrt", "msvcrt"} {
		o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
		o.addSymbol("__imp___msvcrt_assert", 0, 0)
		o.sections[0].relocs = []pe.Reloc{{Type: 4, SymbolTableIndex: 1}}
		p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true, CRT: crt})
		if err != nil {
			t.Fatal(err)
		}
		dll := "ucrtbase.dll"
		if crt == "msvcrt" {
			dll = "msvcrt.dll"
		}
		if len(p.Imports) != 1 || p.Imports[0].Name != "_assert" || p.Imports[0].DLL != dll || !strings.HasSuffix(p.Imports[0].Local, "imp___msvcrt_assert") {
			t.Fatal("CRT export alias/ABI mismatch")
		}
	}
}
