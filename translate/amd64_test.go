package translate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAMD64TrailingImmediateAddends(t *testing.T) {
	// Mach-O SIGNED_1/2/4 already include the trailing immediate in the
	// displacement. A second adjustment silently writes adjacent globals.
	for _, tc := range []struct {
		typ      uint8
		trailing int32
	}{{1, 0}, {6, 1}, {7, 2}, {8, 4}} {
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(-tc.trailing))
		m := objectImage{cpu: macho.CpuAmd64, symbols: []macho.Symbol{{Name: "_target", Type: 1}}, sections: []imageSection{{data: data, relocs: []macho.Reloc{{Type: tc.typ, Len: 2, Extern: true, Pcrel: true}}}}}
		out, err := m.amd64ELFRelocations(0, data, []uint32{1})
		if err != nil {
			t.Fatal(err)
		}
		if got := int64(binary.LittleEndian.Uint64(out[16:])); got != -4-int64(tc.trailing) {
			t.Fatalf("type %d: addend %d", tc.typ, got)
		}
		if binary.LittleEndian.Uint32(out[8:]) != uint32(elf.R_X86_64_PC32) || !bytes.Equal(data, make([]byte, 4)) {
			t.Fatal("incorrect RELA conversion")
		}
	}
}

func TestAMD64LocalGOTReferencesUsePrivateSlots(t *testing.T) {
	// cmp boundary@GOTPCREL(%rip), %rax cannot be relaxed to LEA. Go would bind
	// its GOT entry by name, and dyld aborts on the unexported definition.
	text := []byte{0x48, 0x3b, 0x05, 0, 0, 0, 0, 0x48, 0x03, 0x05, 0, 0, 0, 0, 0x48, 0x3b, 0x05, 0, 0, 0, 0}
	m := objectImage{cpu: macho.CpuAmd64,
		sections: []imageSection{
			{name: "__text", seg: "__TEXT", size: uint64(len(text)), data: text, flags: 0x80000400, relocs: []macho.Reloc{
				{Addr: 3, Value: 0, Type: 4, Len: 2, Extern: true, Pcrel: true},
				{Addr: 10, Value: 0, Type: 4, Len: 2, Extern: true, Pcrel: true},
				{Addr: 17, Value: 1, Type: 4, Len: 2, Extern: true, Pcrel: true},
			}},
			{name: "_CTOR0_ISIZE_FN", seg: "__DATA", addr: 0x20, size: 8, data: make([]byte, 8)},
		},
		symbols: []macho.Symbol{
			{Name: "section$end$__DATA$_CTOR0_ISIZE_FN", Type: 0xf, Sect: 2, Value: 0x28},
			{Name: "_imported", Type: 1},
		},
	}
	n, err := m.localizeAMD64GOTReferences("ns_")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(m.sections) != 3 || len(m.symbols) != 3 {
		t.Fatalf("slots=%d sections=%d symbols=%d", n, len(m.sections), len(m.symbols))
	}
	got := m.sections[2]
	if got.name != "__bao_local_got" || got.seg != "__DATA" || got.addr&7 != 0 || got.size != 8 || len(got.data) != 8 {
		t.Fatalf("slot section %+v", got)
	}
	if len(got.relocs) != 1 || got.relocs[0] != (macho.Reloc{Value: 0, Extern: true, Len: 3}) {
		t.Fatalf("slot relocation %+v", got.relocs)
	}
	relocs := m.sections[0].relocs
	if relocs[0].Type != 1 || relocs[1].Type != 1 || relocs[0].Value != 2 || relocs[1].Value != 2 {
		t.Fatalf("defined references were not localized: %+v", relocs)
	}
	if relocs[2].Type != 4 || relocs[2].Value != 1 {
		t.Fatalf("imported reference must stay a GOT reference: %+v", relocs[2])
	}
	if m.symbols[2].Sect != 3 || m.symbols[2].Value != got.addr || m.symbols[2].Type != 0xe {
		t.Fatalf("slot symbol %+v", m.symbols[2])
	}
	data := bytes.Clone(text)
	out, err := m.amd64ELFRelocations(0, data, []uint32{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(out[8:]) != uint64(3)<<32|uint64(elf.R_X86_64_PC32) || int64(binary.LittleEndian.Uint64(out[16:])) != -4 {
		t.Fatalf("localized RELA %x", out[:24])
	}
	if binary.LittleEndian.Uint32(out[48+8:]) != uint32(elf.R_X86_64_GOTPCREL) {
		t.Fatalf("imported RELA %x", out[48:72])
	}
}

func TestAMD64LocalGOTLeavesEHFrameAndARM64(t *testing.T) {
	eh := imageSection{name: "__eh_frame", seg: "__TEXT", size: 4, data: make([]byte, 4), relocs: []macho.Reloc{{Value: 0, Type: 4, Len: 2, Extern: true, Pcrel: true}}}
	syms := []macho.Symbol{{Name: "_personality", Type: 0xf, Sect: 1}}
	for _, cpu := range []macho.Cpu{macho.CpuAmd64, macho.CpuArm64} {
		m := objectImage{cpu: cpu, sections: []imageSection{eh}, symbols: syms}
		n, err := m.localizeAMD64GOTReferences("ns_")
		if err != nil || n != 0 || len(m.sections) != 1 || m.sections[0].relocs[0].Type != 4 {
			t.Fatalf("%v: n=%d err=%v sections=%d", cpu, n, err, len(m.sections))
		}
	}
}

func TestAMD64ContainerIdentity(t *testing.T) {
	m := objectImage{cpu: macho.CpuAmd64, subCPU: 3, sections: []imageSection{{name: "__text", seg: "__TEXT", size: 1, data: []byte{0xc3}, flags: 0x80000400}}}
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Cpu != macho.CpuAmd64 || f.SubCpu != 3 {
		t.Fatalf("CPU changed: %+v", f.FileHeader)
	}
}

func TestAMD64HelperProvenance(t *testing.T) {
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	b, err := os.ReadFile("native/amd64/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../tls.c", "thunk.S", "tls.bin", "thunk.bin"} {
		b, err := os.ReadFile(filepath.Join("native/amd64", name))
		if err != nil {
			t.Fatal(err)
		}
		if digest(b) != manifest.Files[name] {
			t.Fatalf("%s differs from provenance", name)
		}
	}
}
