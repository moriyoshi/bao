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

// mimalloc: __thread mi_heap_t *_mi_heap_default = &_mi_heap_empty.
func tlsTemplatePointerFixture() *image {
	m := tlsFixture()
	m.sections = append(m.sections,
		section{name: ".tdata.ptr", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS, align: 8, size: 16, data: make([]byte, 16), relocs: []reloc{{off: 8, sym: 2, typ: elf.R_AARCH64_ABS64, add: 4}}},
		section{name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 16, data: make([]byte, 16)})
	m.symbols = append(m.symbols, symbol{name: "heap_empty", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_OBJECT), sect: 5, size: 16})
	return m
}

func TestTLSTemplatePointerMovesToNativeTemplate(t *testing.T) {
	m := tlsTemplatePointerFixture()
	p := &Plan{Namespace: "test_"}
	if err := p.lowerTLS(m); err != nil {
		t.Fatal(err)
	}
	var template *section
	for i := range m.sections {
		if m.sections[i].name == ".bao.tls_template" {
			template = &m.sections[i]
		}
	}
	// .tdata at 0, .tbss at 128..256, then the pointer section at 256.
	if template == nil || len(template.relocs) != 1 || template.relocs[0].off != 264 || template.relocs[0].typ != elf.R_AARCH64_ABS64 || template.relocs[0].sym != 2 || template.relocs[0].add != 4 {
		t.Fatalf("TLS template pointer was not moved to its template offset: %+v", template)
	}
	if len(m.sections[4].relocs) != 0 {
		t.Fatal("lowered TLS section kept its relocation")
	}
	if err := (&Plan{Namespace: "test_"}).bind([]*image{m, thunkHelper()}, map[string]string{}); err != nil {
		t.Fatal(err)
	}
}

// The runtime helper image that defines the TLSDESC thunk.
func thunkHelper() *image {
	return &image{sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 4, data: make([]byte, 4)}}, symbols: []symbol{{}, {name: "test_tls_thunk", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 1, size: 4}}}
}

func TestTLSTemplateImportedPointerBecomesFixup(t *testing.T) {
	m := tlsTemplatePointerFixture()
	m.symbols[2] = symbol{name: "environ", info: byte(elf.STB_GLOBAL) << 4}
	p := &Plan{Namespace: "test_"}
	if err := p.lowerTLS(m); err != nil {
		t.Fatal(err)
	}
	if err := p.bind([]*image{m, thunkHelper()}, map[string]string{"environ": "libc.so.6"}); err != nil {
		t.Fatal(err)
	}
	if len(p.Fixups) != 1 || p.Fixups[0].Addend != 4 {
		t.Fatalf("imported TLS initializer pointer needs a fixup before threads copy the template: %+v", p.Fixups)
	}
	for _, s := range m.symbols {
		if s.name == p.Fixups[0].Location && (m.sections[s.sect].name != ".bao.tls_template" || s.value != 264) {
			t.Fatal("fixup does not patch the native template")
		}
	}
}

func TestTLSTemplateRejectsUnmodeledRelocations(t *testing.T) {
	for _, kind := range []string{"pc-relative", "pointer-to-tls", "pointer-to-tls-section", "truncated", "amd64-pc-relative"} {
		t.Run(kind, func(t *testing.T) {
			m := tlsTemplatePointerFixture()
			r := &m.sections[4].relocs[0]
			switch kind {
			case "pc-relative":
				r.typ = elf.R_AARCH64_PREL64
			case "pointer-to-tls":
				r.sym = 1
			case "pointer-to-tls-section":
				m.symbols[2].sect = 3
			case "truncated":
				r.off = 12
			case "amd64-pc-relative":
				m.machine = elf.EM_X86_64
				r.typ = elf.R_AARCH64(elf.R_X86_64_PC64)
			}
			p := &Plan{Namespace: "test_"}
			if err := p.lowerTLSForMachine(m); err == nil || !strings.Contains(err.Error(), "TLS template") {
				t.Fatalf("unsupported TLS template relocation accepted: %v", err)
			}
		})
	}
}

func TestTLSTemplatePointerOnDynamicTLSTargets(t *testing.T) {
	m, p := amd64TLSFixture(false)
	m.sections[2].relocs = []reloc{{off: 0, sym: 3, typ: elf.R_AARCH64(elf.R_X86_64_64)}}
	m.sections = append(m.sections, section{name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8)})
	m.symbols = append(m.symbols, symbol{name: "heap_empty", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_OBJECT), sect: 3, size: 8})
	if err := p.lowerTLSForMachine(m); err != nil {
		t.Fatal(err)
	}
	for _, s := range m.sections {
		if s.name == ".bao.tls_template" && (len(s.relocs) != 1 || elf.R_X86_64(s.relocs[0].typ) != elf.R_X86_64_64) {
			t.Fatal("amd64 TLS template pointer was not moved")
		}
	}
}

func TestUnreferencedLocalAbsoluteSymbolIsRetired(t *testing.T) {
	abs := symbol{name: "mixin", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE), sect: uint16(elf.SHN_ABS), value: 0x1234}
	text := section{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 8, data: make([]byte, 8)}
	m := &image{sections: []section{{}, text}, symbols: []symbol{{}, abs}}
	if err := normalizeSymbols(m); err != nil || m.symbols[1].sect != 0 || m.symbols[1].name == "mixin" {
		t.Fatal("unreferenced local absolute symbol was not retired", err)
	}
	for _, kind := range []string{"referenced", "global"} {
		m := &image{sections: []section{{}, text}, symbols: []symbol{{}, abs}}
		switch kind {
		case "referenced":
			m.sections[1].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64_ABS64}}
		case "global":
			m.symbols[1].info = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE)
		}
		if err := normalizeSymbols(m); err == nil {
			t.Fatalf("%s absolute symbol accepted", kind)
		}
	}
	// A debug-only reference does not keep the symbol alive.
	m = &image{sections: []section{{}, text, {name: ".debug_info", typ: elf.SHT_PROGBITS, size: 8, data: make([]byte, 8), relocs: []reloc{{sym: 1, typ: elf.R_AARCH64_ABS64}}}}, symbols: []symbol{{}, abs}}
	if err := normalizeSymbols(m); err != nil {
		t.Fatal(err)
	}
}

// b.ne / cbz / tbnz into the same section: OpenSSL poly1305-armv8.
func TestSameSectionShortBranchesResolved(t *testing.T) {
	code := make([]byte, 0x40)
	for i, w := range []uint32{0x54000001, 0xb4000000, 0x37000000, 0xd65f03c0} {
		binary.LittleEndian.PutUint32(code[4*i:], w)
	}
	m := &image{sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: uint64(len(code)), data: code, relocs: []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64_CONDBR19}, {off: 4, sym: 2, typ: elf.R_AARCH64_CONDBR19, add: 0x10}, {off: 8, sym: 1, typ: elf.R_AARCH64_TSTBR14, add: 0x20}}}}, symbols: []symbol{{}, {name: "poly1305_emit", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 1, value: 0x30, size: 4}, {info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_SECTION), sect: 1}}}
	if err := (&Plan{Namespace: "test_"}).bind([]*image{m}, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	text := m.sections[1]
	want := []uint32{0x54000001 | (0x30/4)<<5, 0xb4000000 | (0xc/4)<<5, 0x37000000 | (0x48/4)<<5}
	for i, w := range want {
		if got := binary.LittleEndian.Uint32(text.data[4*i:]); got != w {
			t.Fatalf("branch %d: got %#x, want %#x", i, got, w)
		}
	}
	if len(text.relocs) != 0 {
		t.Fatal("resolved branch relocations reached Go's linker")
	}
	// Backward branches encode negative displacements.
	binary.LittleEndian.PutUint32(text.data[0x3c:], 0x54000000)
	text.relocs = []reloc{{off: 0x3c, sym: 2, typ: elf.R_AARCH64_CONDBR19}}
	m.sections[1] = text
	if err := (&Plan{Namespace: "test_"}).bind([]*image{m}, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	back := int32(-0x3c / 4)
	if got := binary.LittleEndian.Uint32(text.data[0x3c:]); got != 0x54000000|(uint32(back)&0x7ffff)<<5 {
		t.Fatalf("backward branch: %#x", got)
	}
}

func TestShortBranchesOutsideSectionOrRangeRejected(t *testing.T) {
	for _, kind := range []string{"other-section", "import", "tbz-range", "misaligned", "not-a-branch", "condbr-range"} {
		t.Run(kind, func(t *testing.T) {
			code := make([]byte, 16)
			binary.LittleEndian.PutUint32(code, 0x54000001)
			binary.LittleEndian.PutUint32(code[4:], 0x36000000)
			text := section{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 16, data: code}
			other := section{name: ".text.other", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 4, data: make([]byte, 4)}
			m := &image{sections: []section{{}, text, other}, symbols: []symbol{{}, {name: "target", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 1, value: 12}}}
			r := reloc{off: 0, sym: 1, typ: elf.R_AARCH64_CONDBR19}
			switch kind {
			case "other-section":
				m.symbols[1].sect, m.symbols[1].value = 2, 0
			case "import":
				m.symbols[1].sect, m.symbols[1].value = 0, 0
			case "tbz-range":
				r.off, r.typ, r.add = 4, elf.R_AARCH64_TSTBR14, 1<<15
			case "misaligned":
				r.add = 2
			case "not-a-branch":
				binary.LittleEndian.PutUint32(m.sections[1].data, 0xd503201f) // nop
			case "condbr-range":
				r.add = 1 << 20
			}
			m.sections[1].relocs = []reloc{r}
			if err := (&Plan{Namespace: "test_"}).bind([]*image{m}, map[string]string{"target": "libc.so.6"}); err == nil || !strings.Contains(err.Error(), "R_AARCH64_") {
				t.Fatalf("unsupported short branch accepted: %v", err)
			}
		})
	}
}

// libffi's AArch64 trampoline_code_table makes .text 16 KiB-aligned.
func TestTextAlignmentBeyondGoLinkerLimit(t *testing.T) {
	text := section{name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 16384}
	s := text
	if err := (&Plan{}).limitTextAlignment(&s, 0); err == nil || !strings.Contains(err.Error(), "-linux-max-text-alignment 4096") {
		t.Fatalf("over-aligned text accepted without the opt-in: %v", err)
	}
	p := &Plan{}
	if err := p.limitTextAlignment(&s, MaxSafeTextAlignment); err != nil || s.align != 4096 || len(p.CappedTextAlignments) != 1 || p.CappedTextAlignments[0] != (CappedAlignment{".text", 16384, 4096}) {
		t.Fatalf("cap not applied and recorded: %v %+v", err, p.CappedTextAlignments)
	}
	for _, ok := range []section{{name: ".text", flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4096}, {name: ".data", flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 16384}} {
		p := &Plan{}
		if err := p.limitTextAlignment(&ok, 0); err != nil || len(p.CappedTextAlignments) != 0 {
			t.Fatalf("%s at %d must pass unchanged: %v", ok.name, ok.align, err)
		}
	}
	if _, err := TranslateWithOptions(nil, "", nil, Options{MaxTextAlignment: 8192}); err == nil || !strings.Contains(err.Error(), "only 4096") {
		t.Fatalf("unsupported cap value accepted: %v", err)
	}
}
