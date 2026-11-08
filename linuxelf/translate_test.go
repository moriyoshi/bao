package linuxelf

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func tlsFixture() *image {
	code := make([]byte, 16)
	for i, w := range []uint32{0x90000000, 0xf9400001, 0x91000000, 0xd63f0020} {
		binary.LittleEndian.PutUint32(code[i*4:], w)
	}
	types := []elf.R_AARCH64{elf.R_AARCH64_TLSDESC_ADR_PAGE21, elf.R_AARCH64(563), elf.R_AARCH64(564), elf.R_AARCH64_TLSDESC_CALL}
	var rels []reloc
	for i, typ := range types {
		rels = append(rels, reloc{off: uint64(i * 4), sym: 1, typ: typ})
	}
	return &image{sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 16, data: code, relocs: rels}, {name: ".tdata", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS, align: 64, size: 8, data: []byte{42, 0, 0, 0, 0, 0, 0, 0}}, {name: ".tbss", typ: elf.SHT_NOBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS, align: 128, size: 128}}, symbols: []symbol{{}, {name: "tls_value", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_TLS), sect: 2, size: 8}}}
}

func TestTLSDescriptorSemantics(t *testing.T) {
	m := tlsFixture()
	p := &Plan{Namespace: "test_"}
	if err := p.lowerTLS(m); err != nil {
		t.Fatal(err)
	}
	if p.TLSDescriptors != 1 || p.TLSTemplateSize != 256 || p.TLSTemplateAlignment != 128 {
		t.Fatalf("template layout: %+v", p)
	}
	if len(m.sections[1].relocs) != 3 {
		t.Fatal("TLSDESC_CALL relocation was not removed")
	}
	for i, w := range []uint32{0x90000000, 0xf9400001, 0x91000000, 0xd63f0020} {
		if got := binary.LittleEndian.Uint32(m.sections[1].data[i*4:]); got != w {
			t.Fatal("native TLSDESC instructions changed")
		}
	}
	d := m.sections[len(m.sections)-1]
	if len(d.data) != 16 || binary.LittleEndian.Uint64(d.data[8:]) != 0 || len(d.relocs) != 1 {
		t.Fatal("descriptor must contain own thunk and template-relative offset")
	}
	for _, bad := range []string{"instruction", "symbol", "addend", "partial", "template-reloc"} {
		t.Run(bad, func(t *testing.T) {
			m := tlsFixture()
			switch bad {
			case "instruction":
				m.sections[1].data[12] = 0
			case "symbol":
				m.sections[1].relocs[2].sym = 0
			case "addend":
				m.sections[1].relocs[2].add = 1
			case "partial":
				m.sections[1].relocs = m.sections[1].relocs[:3]
			case "template-reloc":
				m.sections[2].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64_ABS64}}
			}
			if err := (&Plan{}).lowerTLS(m); err == nil {
				t.Fatal("unsupported TLS form accepted")
			}
		})
	}
}

func TestTLSDescriptorGCCResolverRegister(t *testing.T) {
	for _, reg := range []uint32{1, 2, 3, 9, 16, 30} {
		m := tlsFixture()
		binary.LittleEndian.PutUint32(m.sections[1].data[4:], 0xf9400000|reg)
		binary.LittleEndian.PutUint32(m.sections[1].data[12:], 0xd63f0000|reg<<5)
		before := append([]byte(nil), m.sections[1].data...)
		if err := (&Plan{Namespace: "gcc_"}).lowerTLS(m); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		if string(before) != string(m.sections[1].data) || len(m.sections[1].relocs) != 3 {
			t.Fatal("register-flexible lowering changed native code or retained call relocation")
		}
	}
	for _, kind := range []string{"clobber-descriptor", "zero-resolver", "wrong-call", "wrong-base", "wrong-add", "nonconsecutive"} {
		t.Run(kind, func(t *testing.T) {
			m := tlsFixture()
			switch kind {
			case "clobber-descriptor":
				binary.LittleEndian.PutUint32(m.sections[1].data[4:], 0xf9400000)
			case "zero-resolver":
				binary.LittleEndian.PutUint32(m.sections[1].data[4:], 0xf940001f)
			case "wrong-call":
				binary.LittleEndian.PutUint32(m.sections[1].data[12:], 0xd63f0060)
			case "wrong-base":
				binary.LittleEndian.PutUint32(m.sections[1].data[4:], 0xf9400021)
			case "wrong-add":
				binary.LittleEndian.PutUint32(m.sections[1].data[8:], 0x91000001)
			case "nonconsecutive":
				m.sections[1].relocs[1].off = 8
			}
			if err := (&Plan{}).lowerTLS(m); err == nil {
				t.Fatal("invalid descriptor call accepted")
			}
		})
	}
}

func TestELFRoundTripAndMachineBoundary(t *testing.T) {
	m := tlsFixture()
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	read, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.sections[1].relocs) != 4 || read.sections[3].align != 128 || read.symbols[1].name != "tls_value" {
		t.Fatal("ELF round trip lost relocation/alignment/symbol")
	}
	binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_S390))
	if _, err := parse(b); err == nil {
		t.Fatal("wrong architecture accepted")
	}
}

func TestLocalGOTAndWeakNULL(t *testing.T) {
	m := &image{sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 24, data: make([]byte, 24)}}, symbols: []symbol{{}, {name: "local", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FUNC), sect: 1, size: 24}, {name: "optional", info: byte(elf.STB_WEAK) << 4, sect: 0}}}
	for i, w := range []uint32{0x90000002, 0xf9400043, 0x90000004, 0xf9400085, 0x94000000, 0xd65f03c0} {
		binary.LittleEndian.PutUint32(m.sections[1].data[4*i:], w)
	}
	m.sections[1].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64_ADR_GOT_PAGE}, {off: 4, sym: 1, typ: elf.R_AARCH64_LD64_GOT_LO12_NC}, {off: 8, sym: 2, typ: elf.R_AARCH64_ADR_GOT_PAGE}, {off: 12, sym: 2, typ: elf.R_AARCH64_LD64_GOT_LO12_NC}, {off: 16, sym: 2, typ: elf.R_AARCH64_CALL26}}
	p := &Plan{Namespace: "test_"}
	if err := p.bind([]*image{m}, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(m.sections[1].data[4:]) != 0x91000043 {
		t.Fatal("local GOT did not relax LDR into ADD")
	}
	if binary.LittleEndian.Uint32(m.sections[1].data[12:]) != 0xf9400085 {
		t.Fatal("missing weak address must LOAD the zero cell")
	}
	if len(p.WeakZero) != 1 || p.WeakZero[0] != "optional" {
		t.Fatal("missing weak not reported")
	}
}

func TestEmbeddedRuntimeProvenance(t *testing.T) {
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	data, err := os.ReadFile("native/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for name, want := range manifest.Files {
		b, err := os.ReadFile("native/" + name)
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(b)
		if strings.ToLower(want) != fmtHash(got) {
			t.Fatalf("%s changed without regenerating native runtime", name)
		}
	}
	if _, err := parse(runtimeObject); err != nil {
		t.Fatal(err)
	}
}

func TestStrongMissingImportOverridesWeakAcrossImages(t *testing.T) {
	strong := &image{sections: []section{{}}, symbols: []symbol{{}, {name: "missing", info: byte(elf.STB_GLOBAL) << 4}}}
	weak := &image{sections: []section{{}}, symbols: []symbol{{}, {name: "missing", info: byte(elf.STB_WEAK) << 4}}}
	for _, images := range [][]*image{{strong, weak}, {weak, strong}} {
		if err := (&Plan{}).bind(images, map[string]string{}); err == nil || !strings.Contains(err.Error(), "does not export missing") {
			t.Fatalf("missing strong import must fail even with a weak reference: %v", err)
		}
	}
}

func TestUnavailableWeakNonzeroAddendRejected(t *testing.T) {
	for _, typ := range []elf.R_AARCH64{elf.R_AARCH64_ABS64, elf.R_AARCH64_ADR_GOT_PAGE, elf.R_AARCH64_LD64_GOT_LO12_NC, elf.R_AARCH64_CALL26} {
		m := &image{sections: []section{{}, {name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8), relocs: []reloc{{off: 0, sym: 1, typ: typ, add: 1}}}}, symbols: []symbol{{}, {name: "missing", info: byte(elf.STB_WEAK) << 4}}}
		if err := (&Plan{}).bind([]*image{m}, map[string]string{}); err == nil || !strings.Contains(err.Error(), "nonzero addend") {
			t.Fatalf("%s accepted unsupported weak addend: %v", typ, err)
		}
	}
}
func fmtHash(h [32]byte) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 64)
	for i, v := range h {
		b[2*i] = hex[v>>4]
		b[2*i+1] = hex[v&15]
	}
	return string(b)
}
