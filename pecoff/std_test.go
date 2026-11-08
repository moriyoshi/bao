package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
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
