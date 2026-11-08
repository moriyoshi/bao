package linuxelf

import (
	"bytes"
	"debug/elf"
	"testing"
)

func TestStripELFDebugPreservesRuntimeAndIndices(t *testing.T) {
	m := &image{machine: elf.EM_PPC64, flags: 2, sections: []section{{}, {name: ".debug_info", typ: elf.SHT_PROGBITS, align: 1, data: []byte("SOURCE-LEVEL-DEBUG-ONLY"), size: 22}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 4, data: []byte{0x20, 0, 0x80, 0x4e}}, {name: ".eh_frame", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, align: 8, size: 8, data: make([]byte, 8), relocs: []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_PPC64_REL64)}}}, {name: ".gcc_except_table", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, align: 1, size: 3, data: []byte{1, 2, 3}}}, symbols: []symbol{{}, {name: "native_fn", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 2, size: 4}, {name: "debug_source", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_OBJECT), sect: 1, size: 22}}}
	original, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(original)
	stripped, count, err := StripDebug(original)
	if err != nil {
		t.Fatal(err)
	}
	if count < 1 || !bytes.Equal(original, before) || bytes.Contains(stripped, []byte("SOURCE-LEVEL-DEBUG-ONLY")) {
		t.Fatal("debug payload remained or original was mutated")
	}
	f, err := elf.NewFile(bytes.NewReader(stripped))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Section(".debug_info") != nil || f.Section(".eh_frame") == nil || f.Section(".gcc_except_table") == nil {
		t.Fatal("debug/runtime section distinction lost")
	}
	again, err := parse(stripped)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range again.sections {
		if s.name == ".eh_frame" {
			if len(s.relocs) != 1 || again.symbols[s.relocs[0].sym].name != "native_fn" {
				t.Fatal("runtime relocation symbol index was corrupted")
			}
		}
	}
	second, n, err := StripDebug(stripped)
	if err != nil || n != 0 || !bytes.Equal(second, stripped) {
		t.Fatal("debug stripping is not idempotent", err)
	}
}

func TestStripELFFileSymbolWithoutDebugSections(t *testing.T) {
	m := tlsFixture()
	m.symbols = append(m.symbols, symbol{name: "/private/source/path.c", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FILE), sect: uint16(elf.SHN_ABS)})
	original, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	stripped, n, err := StripDebug(original)
	if err != nil || n != 0 {
		t.Fatal("file-symbol-only stripping must report zero removed sections", n, err)
	}
	if bytes.Contains(stripped, []byte("/private/source/path.c")) || !bytes.Contains(original, []byte("/private/source/path.c")) {
		t.Fatal("file symbol remained or original was mutated")
	}
	second, n, err := StripDebug(stripped)
	if err != nil || n != 0 || !bytes.Equal(second, stripped) {
		t.Fatal("file-symbol-only stripping is not idempotent", err)
	}
}
