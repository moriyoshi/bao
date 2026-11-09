package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"github.com/moriyoshi/bao/internal/ar"
	"strings"
	"testing"
)

func TestEmbeddedImportDoesNotAuthorizeDLL(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.addSymbol("untrusted", 0, 0)
	o.symbols[1].Type = 0x20
	o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, Type: 4, SymbolTableIndex: 1}}
	record := make([]byte, 20)
	binary.LittleEndian.PutUint16(record[2:], 0xffff)
	binary.LittleEndian.PutUint16(record[6:], 0x8664)
	payload := []byte("untrusted\x00untrusted.dll\x00")
	binary.LittleEndian.PutUint32(record[12:], uint32(len(payload)))
	record = append(record, payload...)
	input, _ := archiveFixture([]ar.Member{{Name: "native.obj", Data: encoded(t, o)}, {Name: "untrusted.dll", Data: record}})
	if _, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true}); err == nil || !strings.Contains(err.Error(), "undefined Windows native symbol") {
		t.Fatalf("embedded DLL declaration granted a binding: %v", err)
	}
	p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true, Imports: map[string]string{"untrusted": "chosen.dll"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Imports) != 1 || p.Imports[0].DLL != "chosen.dll" {
		t.Fatal("explicit mapping was replaced by archive metadata")
	}
}
func TestLinkerRemovePayloadHasNoRuntimeAddress(t *testing.T) {
	for _, debug := range []bool{false, true} {
		o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
		o.sections = append(o.sections, section{name: ".llvmbc", flags: pe.IMAGE_SCN_MEM_READ | imageSCNLinkRemove, size: 7, data: []byte("BITCODE")})
		o.addSymbol("metadata", 2, 0)
		p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: debug})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(p.Objects[0], []byte("BITCODE")) || len(p.Alignments) != 0 {
			t.Fatal("nonruntime bitcode was retained or given an accessor")
		}
		o.sections[0].relocs = []pe.Reloc{{Type: 1, SymbolTableIndex: 1}}
		if _, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: debug}); err == nil {
			t.Fatal("runtime reference into removed bitcode accepted")
		}
	}
}
func TestTLSImportAliasIsBounded(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		machine, rel := uint16(0x8664), uint16(1)
		if arch == "arm64" {
			machine, rel = 0xaa64, 14
		}
		makeAlias := func() *object {
			o := fixture(machine)
			o.sections = append(o.sections, section{name: ".tls$", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE, size: 8, data: make([]byte, 8)}, section{name: ".data$alias", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: 8, data: make([]byte, 8), relocs: []pe.Reloc{{Type: rel, SymbolTableIndex: 1}}})
			o.addSymbol("tls_value", 2, 0)
			o.addSymbol("__imp_tls_value", 3, 0)
			return o
		}
		o := makeAlias()
		if !o.tlsImportAlias(2, o.sections[2].relocs[0], arch) {
			t.Fatal("compiler TLS alias rejected")
		}
		for name, mutate := range map[string]func(*object){"code": func(o *object) { o.sections[2].flags |= pe.IMAGE_SCN_CNT_CODE }, "addend": func(o *object) { o.sections[2].data[0] = 1 }, "wrong alias": func(o *object) { o.names[2] = "ordinary_pointer" }, "extra definition": func(o *object) { o.addSymbol("other", 3, 0) }, "bounds": func(o *object) { o.sections[2].relocs[0].VirtualAddress = 4 }} {
			t.Run(arch+name, func(t *testing.T) {
				o := makeAlias()
				mutate(o)
				if o.tlsImportAlias(2, o.sections[2].relocs[0], arch) {
					t.Fatal("unbounded TLS pointer accepted")
				}
			})
		}
	}
}
func TestNativeFLSCoordinationKeepsOverrides(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.addSymbol("__imp_FlsAlloc", 0, 0)
	o.addSymbol("FlsGetValue", 0, 0)
	o.addSymbol("FlsFree", 0, 0)
	coordinateNativeFLS([]*object{o}, map[string]int{"FlsFree": 0})
	if o.names[1] != "__imp_bao_winrt_fls_alloc" || o.names[2] != "bao_winrt_fls_get" || o.names[3] != "FlsFree" {
		t.Fatal("native callback coordination ignored an explicit native definition")
	}
}

func importLibraryFixture(t *testing.T, machine uint16, name, dll string, kind uint16) []byte {
	t.Helper()
	record := make([]byte, 20)
	binary.LittleEndian.PutUint16(record[2:], 0xffff)
	binary.LittleEndian.PutUint16(record[6:], machine)
	payload := []byte(name + "\x00" + dll + "\x00")
	binary.LittleEndian.PutUint32(record[12:], uint32(len(payload)))
	binary.LittleEndian.PutUint16(record[18:], kind)
	library, err := archiveFixture([]ar.Member{{Name: "import.dll", Data: append(record, payload...)}})
	if err != nil {
		t.Fatal(err)
	}
	return library
}

func bareReference(t *testing.T, name string, opcode ...byte) []byte {
	t.Helper()
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.addSymbol(name, 0, 0)
	copy(o.sections[0].data[4-len(opcode):], opcode)
	o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, Type: 4, SymbolTableIndex: 1}}
	return encoded(t, o)
}

func TestBareImportDirectBranchForms(t *testing.T) {
	mapped := map[string]string{"SysFreeString": "oleaut32.dll"}
	for _, tc := range []struct {
		name   string
		opcode []byte
		ok     bool
	}{
		{"call", []byte{0xe8}, true},
		{"jmp", []byte{0xe9}, true},
		{"jne", []byte{0x0f, 0x85}, true},
		{"ja", []byte{0x0f, 0x87}, true},
		{"lea", []byte{0x48, 0x8d, 0x0d}, false},
		{"mov", []byte{0x48, 0x8b, 0x05}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Translate(bareReference(t, "SysFreeString", tc.opcode...), Options{Symbols: []string{"example"}, StripDebug: true, Imports: mapped})
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "must be a function")) {
				t.Fatalf("address reference accepted: %v", err)
			}
		})
	}
}

func TestImportLibraryGrantsOnlyNamedFunctions(t *testing.T) {
	const code, data = uint16(1 << 2), uint16(1<<2 | 1)
	amd64 := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	lea := []byte{0x48, 0x8d, 0x0d}
	opts := func(libs ...[]byte) Options {
		return Options{Symbols: []string{"example"}, StripDebug: true, ImportLibraries: libs}
	}
	p, err := Translate(bareReference(t, "CallWindowProcW", lea...), opts(importLibraryFixture(t, amd64, "CallWindowProcW", "USER32.dll", code)))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Imports) != 1 || p.Imports[0].DLL != "user32.dll" {
		t.Fatalf("imports %+v", p.Imports)
	}
	if _, err = Translate(bareReference(t, "SomeData", lea...), opts(importLibraryFixture(t, amd64, "SomeData", "user32.dll", data))); err == nil || !strings.Contains(err.Error(), "undefined Windows native symbol") {
		t.Fatalf("data record granted a binding: %v", err)
	}
	if _, err = Translate(bareReference(t, "CallWindowProcW", lea...), opts(importLibraryFixture(t, uint16(pe.IMAGE_FILE_MACHINE_ARM64), "CallWindowProcW", "user32.dll", code))); err == nil || !strings.Contains(err.Error(), "no short import records") {
		t.Fatalf("wrong-machine library accepted: %v", err)
	}
	// Built-in bindings keep the producer's CRT choice over a library's API set.
	p, err = Translate(bareReference(t, "malloc", 0xe8), opts(importLibraryFixture(t, amd64, "malloc", "api-ms-win-crt-heap-l1-1-0.dll", code)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Imports[0].DLL != "ucrtbase.dll" {
		t.Fatalf("library replaced built-in binding: %+v", p.Imports)
	}
	first := importLibraryFixture(t, amd64, "Shared", "first.dll", code)
	second := importLibraryFixture(t, amd64, "Shared", "second.dll", code)
	if p, err = Translate(bareReference(t, "Shared", 0xe8), opts(first, second)); err != nil || p.Imports[0].DLL != "first.dll" {
		t.Fatalf("first library must win: %+v %v", p, err)
	}
}

func TestUnresolvedImportsReportedTogether(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.addSymbol("zeta", 0, 0)
	o.addSymbol("alpha", 0, 0)
	o.addSymbol("BareData", 0, 0)
	o.sections[0].data[11] = 0x8d
	o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 2, Type: 4, SymbolTableIndex: 1}, {VirtualAddress: 6, Type: 4, SymbolTableIndex: 2}, {VirtualAddress: 12, Type: 4, SymbolTableIndex: 3}}
	_, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true, Imports: map[string]string{"BareData": "some.dll"}})
	var unresolved *ImportError
	if !errors.As(err, &unresolved) {
		t.Fatalf("error %T: %v", err, err)
	}
	if strings.Join(unresolved.Undefined, ",") != "alpha,zeta" || strings.Join(unresolved.Bare, ",") != "BareData" {
		t.Fatalf("collected %+v", unresolved)
	}
	for _, want := range []string{"2 undefined Windows native symbols", `"alpha", "zeta"`, `bare Windows import "BareData"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q missing from %v", want, err)
		}
	}
}

func TestMaxDataAlignmentIsOptInAndReadOnly(t *testing.T) {
	const align64 = 7 << 20
	readOnly := uint32(pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | align64)
	input := func(flags uint32) []byte {
		o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
		o.sections = append(o.sections, section{name: ".rdata", flags: flags, size: 64, data: make([]byte, 64)})
		return encoded(t, o)
	}
	opts := Options{Symbols: []string{"example"}, StripDebug: true}
	if _, err := Translate(input(readOnly), opts); err == nil || !strings.Contains(err.Error(), "requests alignment 64") {
		t.Fatalf("default must reject: %v", err)
	}
	opts.MaxDataAlignment = 32
	p, err := Translate(input(readOnly), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.CappedAlignments) != 1 || p.CappedAlignments[0] != (CappedAlignment{".rdata", 64, 32}) {
		t.Fatalf("recorded %+v", p.CappedAlignments)
	}
	if len(p.Alignments) != 1 || p.Alignments[0].Bytes != 32 {
		t.Fatalf("runtime check %+v", p.Alignments)
	}
	if _, err := Translate(input(readOnly|pe.IMAGE_SCN_MEM_WRITE), opts); err == nil || !strings.Contains(err.Error(), "requests alignment 64") {
		t.Fatalf("writable data capped: %v", err)
	}
	if _, err := Translate(input(uint32(pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_READ|pe.IMAGE_SCN_MEM_EXECUTE|align64)), opts); err == nil || !strings.Contains(err.Error(), "requests alignment 64") {
		t.Fatalf("code capped: %v", err)
	}
	opts.MaxDataAlignment = 16
	if _, err := Translate(input(readOnly), opts); err == nil || !strings.Contains(err.Error(), "only 32") {
		t.Fatalf("unsupported value accepted: %v", err)
	}
}
