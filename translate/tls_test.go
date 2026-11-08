package translate

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
)

func completeTLSFixture() Object {
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code, 0x90000000)
	binary.LittleEndian.PutUint32(code[4:], 0xf9400000)
	initial := make([]byte, 8)
	binary.LittleEndian.PutUint64(initial, 41)
	return fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, code, []macho.Reloc{
			{Addr: 0, Value: 0, Type: 8, Len: 2, Extern: true, Pcrel: true},
			{Addr: 4, Value: 0, Type: 9, Len: 2, Extern: true},
		}},
		{"__thread_data", "__DATA", 0x11, initial, nil},
		{"__thread_bss", "__DATA", 0x12, make([]byte, 16), nil},
		{"__thread_vars", "__DATA", 0x13, make([]byte, 48), []macho.Reloc{
			{Addr: 0, Value: 4, Type: 0, Len: 3, Extern: true},
			{Addr: 16, Value: 2, Type: 0, Len: 3, Extern: true},
			{Addr: 24, Value: 4, Type: 0, Len: 3, Extern: true},
			{Addr: 40, Value: 3, Type: 0, Len: 3, Extern: true},
		}},
	}, []macho.Symbol{
		{Name: "_descriptor", Type: 0xf, Sect: 4, Value: 32},
		{Name: "_descriptor2", Type: 0xf, Sect: 4, Value: 56},
		{Name: "_initial", Type: 0xe, Sect: 2, Value: 8},
		{Name: "_zero", Type: 0xe, Sect: 3, Value: 16},
		{Name: "__tlv_bootstrap", Type: 1},
		{Name: "__tlv_atexit", Type: 1},
	})
}

func TestTLSImageOffsetsAndTemplate(t *testing.T) {
	o := completeTLSFixture()
	original := bytes.Clone(o.Data)
	p, err := LowerTLS(o)
	if err != nil {
		t.Fatal(err)
	}
	if p.Descriptors != 2 || p.TemplateSize != 24 || p.TemplateAlignment != 8 || p.Relocations != 2 {
		t.Fatalf("bad plan: %+v", p)
	}
	if !bytes.Equal(o.Data, original) {
		t.Fatal("mutated original")
	}
	m, err := readImage(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	desc := m.sections[3]
	if got := binary.LittleEndian.Uint64(desc.data[16:]); got != 0 {
		t.Fatalf("initialized TLS offset=%d", got)
	}
	if got := binary.LittleEndian.Uint64(desc.data[40:]); got != 8 {
		t.Fatalf("BSS TLS offset=%d", got)
	}
	if len(desc.relocs) != 2 || desc.flags&0xff != 0 {
		t.Fatal("descriptor relocations/section role were not lowered")
	}
	tmpl := m.sections[len(m.sections)-1]
	expected := make([]byte, 24)
	binary.LittleEndian.PutUint64(expected, 41)
	if !bytes.Equal(tmpl.data, expected) {
		t.Fatalf("template mismatch: %x", tmpl.data)
	}
	if m.sections[2].flags&0xff != 1 {
		t.Fatal("native TLS BSS not preserved as zero-fill")
	}
	r, err := Inspect(o.Data, p.Objects)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Unresolved {
		if u == "__tlv_bootstrap" || u == "__tlv_atexit" {
			t.Fatalf("unhandled native TLS import: %s", u)
		}
	}
	if hasCode(r, "tls-lifecycle") || hasCode(r, "tlvp-relocation") {
		t.Fatal("TLS semantics not lowered")
	}
	if !hasCode(r, "unwind-metadata") {
		t.Fatal("unverified runtime unwind metadata was silently certified")
	}
}

func TestTLSRejectsUnexpectedDescriptor(t *testing.T) {
	for _, mode := range []string{"key", "offset", "template-relocation", "terminator-section"} {
		t.Run(mode, func(t *testing.T) {
			o := completeTLSFixture()
			m, err := readImage(o)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "key":
				binary.LittleEndian.PutUint64(m.sections[3].data[8:], 1)
			case "offset":
				binary.LittleEndian.PutUint64(m.sections[3].data[16:], 999)
			case "template-relocation":
				m.sections[1].relocs = []macho.Reloc{{Type: 0, Len: 3, Extern: true, Value: 2}}
			case "terminator-section":
				m.sections[2].flags = 0x15
			}
			o.Data, err = m.encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := LowerTLS(o); err == nil {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}

func TestObjectRoundTripKeepsRawNamesAndNativeBytes(t *testing.T) {
	o := completeTLSFixture()
	m, err := readImage(o)
	if err != nil {
		t.Fatal(err)
	}
	m.symbols[0].Name = "_raw.dotted.symbol"
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := readImage(Object{Name: o.Name, Data: b})
	if err != nil {
		t.Fatal(err)
	}
	if m2.symbols[0].Name != "_raw.dotted.symbol" {
		t.Fatal("debug/macho name normalization leaked into rewritten output")
	}
	for i, s := range m.sections {
		if s.addr != m2.sections[i].addr || !bytes.Equal(s.data, m2.sections[i].data) {
			t.Fatalf("section %d changed", i)
		}
	}
}

func TestEmbeddedRuntimeProvenance(t *testing.T) {
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	b, err := os.ReadFile("native/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls.c", "thunk.S", "tls.bin", "thunk.bin"} {
		b, err := os.ReadFile("native/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := digest(b); got != manifest.Files[name] {
			t.Fatalf("%s differs from native manifest; rebuild deliberately", name)
		}
	}
	if sha256.Sum256(tlsRuntime) != sha256.Sum256(mustRead(t, "native/tls.bin")) || sha256.Sum256(tlsThunk) != sha256.Sum256(mustRead(t, "native/thunk.bin")) {
		t.Fatal("embedded runtime differs from verified source-tree artifact")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
