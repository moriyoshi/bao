package linuxelf

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossELFMachineAndABIRoundTrip(t *testing.T) {
	for _, row := range []struct {
		machine elf.Machine
		flags   uint32
	}{{elf.EM_LOONGARCH, 0x43}, {elf.EM_PPC64, 2}} {
		m := tlsFixture()
		m.machine = row.machine
		m.flags = row.flags
		b, err := m.encode()
		if err != nil {
			t.Fatal(err)
		}
		again, err := parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if again.machine != row.machine || again.flags != row.flags {
			t.Fatal("target machine/ABI flags were lost")
		}
		if row.machine == elf.EM_PPC64 {
			binary.LittleEndian.PutUint32(b[48:], 1)
			if _, err := parse(b); err == nil {
				t.Fatal("PowerPC ELFv1 was accepted")
			}
		}
	}
}

func TestLoongArchUnsupportedABIsRejectBeforeLowering(t *testing.T) {
	m := tlsFixture()
	m.machine = elf.EM_LOONGARCH
	m.flags = 0x43
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		flags uint32
		want  string
	}{{0x41, "LP64D"}, {0x42, "LP64D"}, {0x40, "LP64D"}, {0x03, "object ABI v1"}, {0x83, "object ABI v1"}, {0xc3, "object ABI v1"}} {
		binary.LittleEndian.PutUint32(b[48:], tc.flags)
		if _, err := parse(b); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("e_flags %#x: expected %q rejection, got %v", tc.flags, tc.want, err)
		}
	}
}

func TestLoongArchBackwardCallsPreserveContinuationSlot(t *testing.T) {
	m := &image{machine: elf.EM_LOONGARCH, flags: 0x43, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 16, data: make([]byte, 16)}}, symbols: []symbol{{}, {name: "backward", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FUNC), sect: 1, size: 16}}}
	binary.LittleEndian.PutUint32(m.sections[1].data[8:], 0x1e000001)
	binary.LittleEndian.PutUint32(m.sections[1].data[12:], 0x4c000021)
	m.sections[1].relocs = []reloc{{off: 8, sym: 1, typ: elf.R_AARCH64(elf.R_LARCH_CALL36)}}
	if err := (&Plan{}).normalizeCross(m, 0); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(m.sections[1].data[8:]) != 0x54000000 || binary.LittleEndian.Uint32(m.sections[1].data[12:]) != 0x03400000 || elf.R_LARCH(m.sections[1].relocs[0].typ) != elf.R_LARCH_B26 {
		t.Fatal("CALL36 must become BL plus retained NOP, with B26 relocation")
	}
	// Unknown register link conventions cannot be silently rewritten.
	binary.LittleEndian.PutUint32(m.sections[1].data[8:], 0x1e000001)
	binary.LittleEndian.PutUint32(m.sections[1].data[12:], 0x4c000022)
	m.sections[1].relocs[0].typ = elf.R_AARCH64(elf.R_LARCH_CALL36)
	if err := (&Plan{}).normalizeCross(m, 0); err == nil {
		t.Fatal("unsupported CALL36 link register accepted")
	}
}

func TestLoongArchDifferenceAndULEBFolding(t *testing.T) {
	m := &image{machine: elf.EM_LOONGARCH, flags: 0x43, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 256, data: make([]byte, 256)}, {name: ".gcc_except_table", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, align: 1, size: 6, data: []byte{0x80, 0, 0, 0, 0, 0}}}, symbols: []symbol{{}, {name: "start", sect: 1, value: 8}, {name: "end", sect: 1, value: 160}}}
	m.sections[2].relocs = []reloc{{off: 0, sym: 2, typ: elf.R_AARCH64(elf.R_LARCH_ADD_ULEB128)}, {off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_LARCH_SUB_ULEB128)}, {off: 2, sym: 2, typ: elf.R_AARCH64(elf.R_LARCH_ADD32)}, {off: 2, sym: 1, typ: elf.R_AARCH64(elf.R_LARCH_SUB32)}}
	if err := (&Plan{}).normalizeCross(m, 0); err != nil {
		t.Fatal(err)
	}
	value, n := binary.Uvarint(m.sections[2].data)
	if value != 152 || n != 2 || binary.LittleEndian.Uint32(m.sections[2].data[2:]) != 152 || len(m.sections[2].relocs) != 0 {
		t.Fatal("LSDA differences or reserved ULEB width lost")
	}
}

func TestNativeRelativeDataFixupKeepsCodeImmutable(t *testing.T) {
	m := &image{machine: elf.EM_PPC64, flags: 2, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 8, data: make([]byte, 8)}, {name: ".eh_frame", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, align: 8, size: 8, data: make([]byte, 8)}}, symbols: []symbol{{}, {name: "native", sect: 1, value: 4}}}
	m.sections[2].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_REL64), add: 7}}
	p := &Plan{Namespace: "test_"}
	if err := p.normalizeCross(m, 0); err != nil {
		t.Fatal(err)
	}
	if len(p.LocalFixups) != 1 || p.LocalFixups[0].Addend != 11 || m.sections[2].flags&elf.SHF_WRITE == 0 || len(m.sections[2].relocs) != 0 {
		t.Fatal("relative native metadata fixup incorrect")
	}
	if m.sections[1].flags&elf.SHF_WRITE != 0 {
		t.Fatal("native text was made writable")
	}
	m.sections[1].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_REL64)}}
	if err := p.normalizeCross(m, 0); err == nil {
		t.Fatal("runtime executable-code data fixup was accepted")
	}
}

func TestPowerPCLocalDynamicOffsets(t *testing.T) {
	m := tlsFixture()
	m.machine = elf.EM_PPC64
	m.flags = 2
	m.sections[1].data = make([]byte, 20)
	m.sections[1].size = 20
	for i, w := range []uint32{0x3c620000, 0x38630000, 0x48000001, 0x3c630000, 0x88630000} {
		binary.LittleEndian.PutUint32(m.sections[1].data[i*4:], w)
	}
	m.symbols = append(m.symbols, symbol{name: "test_tls_resolver", info: byte(elf.STB_GLOBAL) << 4})
	m.symbols[1].value = 3
	m.symbols[1].size = 5 // Keep the offset probe within its eight-byte template.
	m.sections[1].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_GOT_TLSLD16_HA)}, {off: 4, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_GOT_TLSLD16_LO)}, {off: 8, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_TLSLD)}, {off: 8, sym: 2, typ: elf.R_AARCH64(elf.R_PPC64_REL24)}, {off: 12, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_DTPREL16_HA)}, {off: 16, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_DTPREL16_LO)}}
	original, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	p := &Plan{Namespace: "test_"}
	if err := p.lowerDynamicTLS(m); err != nil {
		t.Fatal(err)
	}
	if p.TLSDescriptors != 1 || len(m.sections[1].relocs) != 3 || binary.LittleEndian.Uint16(m.sections[1].data[16:]) != 3 {
		t.Fatal("local-dynamic TLS must use native block base plus its template offset")
	}
	again, err := parse(original)
	if err != nil {
		t.Fatal(err)
	}
	rels := again.sections[1].relocs
	rels[2], rels[3] = rels[3], rels[2]
	if err := (&Plan{Namespace: "test_"}).lowerDynamicTLS(again); err != nil {
		t.Fatalf("equivalent same-address GNU marker ordering rejected: %v", err)
	}
}

func TestCrossRuntimeProvenance(t *testing.T) {
	for _, arch := range []string{"amd64", "loong64", "ppc64le"} {
		var manifest struct {
			Files map[string]string `json:"files"`
		}
		dir := filepath.Join("native", arch)
		b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &manifest); err != nil {
			t.Fatal(err)
		}
		for name, want := range manifest.Files {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if got := fmtHash(sha256.Sum256(b)); got != want {
				t.Fatalf("%s/%s requires helper regeneration", arch, name)
			}
		}
		b, err = os.ReadFile(filepath.Join(dir, "runtime.bin"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if m.arch() != arch {
			t.Fatalf("%s helper has %s ABI", arch, m.arch())
		}
	}
}

func TestLoongGCCNormalTLSResolverCall(t *testing.T) {
	m := tlsFixture()
	m.machine = elf.EM_LOONGARCH
	m.flags = 0x43
	m.sections[1].data = make([]byte, 20)
	m.sections[1].size = 20
	for i, w := range []uint32{0x1a000004, 0x02c00084, 0x03400000, 0x54000000, 0x4c000020} {
		binary.LittleEndian.PutUint32(m.sections[1].data[4*i:], w)
	}
	m.symbols = append(m.symbols, symbol{name: "test_tls_lookup", info: byte(elf.STB_GLOBAL) << 4})
	m.sections[1].relocs = []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_LARCH_TLS_LD_PC_HI20)}, {off: 4, sym: 1, typ: elf.R_AARCH64(elf.R_LARCH_GOT_PC_LO12)}, {off: 12, sym: 2, typ: elf.R_AARCH64(elf.R_LARCH_B26)}}
	if err := (&Plan{Namespace: "test_"}).lowerDynamicTLS(m); err != nil {
		t.Fatal("GCC's standard C ABI B26 resolver call was rejected", err)
	}
	if len(m.sections[1].relocs) != 3 || elf.R_LARCH(m.sections[1].relocs[2].typ) != elf.R_LARCH_B26 {
		t.Fatal("GCC resolver branch was changed")
	}
}
