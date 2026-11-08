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
