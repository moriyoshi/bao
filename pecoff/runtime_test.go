package pecoff

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/internal/ar"
)

func TestWindowsHelperProvenance(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		base := filepath.Join("native", arch)
		data, err := os.ReadFile(filepath.Join(base, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Files map[string]string `json:"files"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		for name, want := range manifest.Files {
			data, err := os.ReadFile(filepath.Join(base, name))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(data)) != want {
				t.Fatalf("Windows %s helper provenance changed: %s", arch, name)
			}
		}
	}
}

func addWeak(o *object, name string, target, mode uint32) uint32 {
	i := uint32(len(o.symbols))
	o.addSymbol(name, 0, 0)
	o.symbols[i].StorageClass = 105
	o.symbols[i].NumberOfAuxSymbols = 1
	raw := make([]byte, 18)
	binary.LittleEndian.PutUint32(raw, target)
	binary.LittleEndian.PutUint32(raw[4:], mode)
	var aux pe.COFFSymbol
	binary.Read(bytes.NewReader(raw), binary.LittleEndian, &aux)
	o.symbols = append(o.symbols, aux)
	o.names = append(o.names, "")
	return i
}
func TestWeakSearchAndStrongOverride(t *testing.T) {
	for _, mode := range []uint32{1, 2, 3} {
		for _, strongRoot := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode%d-strong%v", mode, strongRoot), func(t *testing.T) {
				o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
				o.addSymbol("fallback", 1, 8)
				o.symbols[1].Type = 0x20
				weak := addWeak(o, "optional", 1, mode)
				o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: weak, Type: 4}}
				strong := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
				strong.names[0] = "optional"
				input, err := archiveFixture([]ar.Member{{Name: "weak.obj", Data: encoded(t, o)}, {Name: "strong.obj", Data: encoded(t, strong)}})
				if err != nil {
					t.Fatal(err)
				}
				roots := []string{"example"}
				if strongRoot {
					roots = append(roots, "optional")
				}
				p, err := Translate(input, Options{Symbols: roots, StripDebug: true})
				if err != nil {
					t.Fatal(err)
				}
				got, err := parse(p.Objects[0])
				if err != nil {
					t.Fatal(err)
				}
				want := "fallback"
				count := 1
				if strongRoot || mode == 2 {
					want = "optional"
					count = 2
				}
				if len(p.Objects) != count || got.names[got.sections[0].relocs[0].SymbolTableIndex] != p.Namespace+want {
					t.Fatalf("weak search semantics: %s, members %d", got.names[got.sections[0].relocs[0].SymbolTableIndex], len(p.Objects))
				}
			})
		}
	}
	for _, bad := range []string{"cycle", "index", "policy", "record"} {
		t.Run(bad, func(t *testing.T) {
			o := fixture(pe.IMAGE_FILE_MACHINE_ARM64)
			target, mode := uint32(0), uint32(3)
			switch bad {
			case "cycle":
				target = 1
			case "index":
				target = 999
			case "policy":
				mode = 4
			}
			i := addWeak(o, "optional", target, mode)
			if bad == "record" {
				o.symbols[i].Value = 4
			}
			o.sections[0].relocs = []pe.Reloc{{Type: 3, SymbolTableIndex: i}}
			if _, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}}); err == nil {
				t.Fatal("malformed weak record accepted")
			}
		})
	}
}

func TestCRTTablesAndUnwindData(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		o := fixture(machine)
		for _, name := range []string{".CRT$XIU", ".CRT$XPU", ".CRT$XTU", ".CRT$XLB", ".CRT$XDU", ".dtors"} {
			o.sections = append(o.sections, section{name: name, size: 8, data: make([]byte, 8), flags: pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_CNT_INITIALIZED_DATA})
		}
		o.sections = append(o.sections, section{name: ".xdata", size: 16, data: make([]byte, 16), flags: pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_CNT_INITIALIZED_DATA})
		o.addSymbol("ehdata", int16(len(o.sections)), 0)
		p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
		if err != nil {
			t.Fatal(err)
		}
		if !p.Runtime || len(p.CInitializers) != 1 || len(p.PreTerminators) != 1 || len(p.Terminators) != 2 || len(p.TLSCallbacks) != 1 || len(p.TLSInitializers) != 1 {
			t.Fatal("CRT lifecycle plan incomplete")
		}
		got, err := parse(p.Objects[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range got.sections {
			if s.name == ".xdata" {
				t.Fatal("native EH data still has Go-special placement")
			}
		}
	}
}

func TestCRTDirectiveBoundaries(t *testing.T) {
	for _, directive := range []string{"/DEFAULTLIB:LIBCMT", "/DEFAULTLIB:evil", "/FAILIFMISMATCH:RuntimeLibrary=MT_StaticRelease", "/INCLUDE:missing", "/ALTERNATENAME:a=a"} {
		o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
		o.sections = append(o.sections, section{name: ".drectve", data: []byte(directive), size: uint32(len(directive)), flags: 0x200})
		if strings.Contains(directive, "ALTERNATENAME") {
			o.addSymbol("a", 0, 0)
			o.sections[0].relocs = []pe.Reloc{{Type: 4, VirtualAddress: 4, SymbolTableIndex: 1}}
		}
		if _, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}}); err == nil {
			t.Fatalf("unsafe directive accepted: %s", directive)
		}
	}
}

func TestTLSAccessValidation(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		for _, bad := range []string{"", "load", "relocation", "template", "symbol"} {
			t.Run(fmt.Sprintf("%x-%s", machine, bad), func(t *testing.T) {
				o := fixture(machine)
				o.sections[0].size = 32
				o.sections[0].data = make([]byte, 32)
				o.sections = append(o.sections, section{name: ".tls$AA", size: 16, data: make([]byte, 16), flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | 0x500000})
				o.addSymbol("tls_value", 2, 4)
				o.addSymbol("_tls_index", 0, 0)
				if machine == pe.IMAGE_FILE_MACHINE_AMD64 {
					copy(o.sections[0].data, []byte{0x8b, 0x05})
					copy(o.sections[0].data[8:], []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x58, 0, 0, 0})
					o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 2, SymbolTableIndex: 2, Type: 4}, {VirtualAddress: 24, SymbolTableIndex: 1, Type: 0xb}}
					if bad == "load" {
						o.sections[0].data[9] = 0x40
					}
				} else {
					binary.LittleEndian.PutUint32(o.sections[0].data, 0x90000008)
					binary.LittleEndian.PutUint32(o.sections[0].data[4:], 0xf9402e49)
					binary.LittleEndian.PutUint32(o.sections[0].data[16:], 0x91000108)
					o.sections[0].relocs = []pe.Reloc{{SymbolTableIndex: 2, Type: 4}, {VirtualAddress: 16, SymbolTableIndex: 1, Type: 9}}
					if bad == "load" {
						o.sections[0].data[4] = 0
					}
				}
				switch bad {
				case "relocation":
					o.sections[0].relocs[1].Type = 14
				case "template":
					o.sections[1].relocs = []pe.Reloc{{Type: 14}}
				case "symbol":
					o.symbols[1].Value = 16
				}
				input := encoded(t, o)
				p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true})
				if bad != "" {
					if err == nil {
						t.Fatal("unrecognized TLS access accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !p.Runtime || p.TLS.Symbol == "" || p.TLS.Alignment != 16 || p.TLS.Accesses < 1 {
					t.Fatalf("missing private TLS plan: %+v", p.TLS)
				}
				if !bytes.Equal(input, encoded(t, o)) {
					t.Fatal("TLS translation changed source input")
				}
			})
		}
	}
}

func TestCommonCoalescingAndStrongPrecedence(t *testing.T) {
	for _, strong := range []bool{false, true} {
		a := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
		a.addSymbol("data", 0, 8)
		a.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: 1, Type: 4}}
		b := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
		b.names[0] = "second"
		b.addSymbol("data", 0, 40)
		members := []ar.Member{{Name: "a.obj", Data: encoded(t, a)}, {Name: "b.obj", Data: encoded(t, b)}}
		if strong {
			s := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
			s.names[0] = "data"
			s.symbols[0].Type = 0
			members = append(members, ar.Member{Name: "strong.obj", Data: encoded(t, s)})
		}
		input, err := archiveFixture(members)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Translate(input, Options{Symbols: []string{"example"}, StripDebug: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Objects) != 2 {
			t.Fatalf("common closure: %d objects", len(p.Objects))
		}
		got, err := parse(p.Objects[1])
		if err != nil {
			t.Fatal(err)
		}
		if !strong && (got.sections[0].size != 40 || got.sections[0].flags&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0) {
			t.Fatal("largest common size not retained")
		}
		if strong && got.sections[0].flags&pe.IMAGE_SCN_CNT_CODE == 0 {
			t.Fatal("strong definition did not override common")
		}
	}
}

func TestNullWeakAddressAndUnreachableCall(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		o := fixture(machine)
		o.addSymbol("zero_fallback", -1, 0)
		weak := addWeak(o, "optional", 1, 1)
		pointer, call := uint16(1), uint16(4)
		if machine == pe.IMAGE_FILE_MACHINE_AMD64 {
			o.sections[0].data[3] = 0xe8
		} else {
			pointer = 14
			call = 3
			binary.LittleEndian.PutUint32(o.sections[0].data[4:], 0x94000000)
		}
		o.sections[0].relocs = []pe.Reloc{{VirtualAddress: 4, SymbolTableIndex: weak, Type: call}}
		o.sections = append(o.sections, section{name: ".rdata", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ, size: 8, data: make([]byte, 8), relocs: []pe.Reloc{{SymbolTableIndex: weak, Type: pointer}}})
		p, err := Translate(encoded(t, o), Options{Symbols: []string{"example"}, StripDebug: true})
		if err != nil {
			t.Fatal(err)
		}
		got, err := parse(p.Objects[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(got.sections[1].relocs) != 0 || binary.LittleEndian.Uint64(got.sections[1].data) != 0 {
			t.Fatal("missing weak address became nonnull")
		}
		r := got.sections[0].relocs[0]
		if got.symbols[r.SymbolTableIndex].SectionNumber <= 2 {
			t.Fatal("unreachable null call lacks a local tail jump")
		}
	}
}
