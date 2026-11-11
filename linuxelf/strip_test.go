package linuxelf

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
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

func TestStripELFBitcodeKeepsDebugAndRuntime(t *testing.T) {
	bitcode := []byte("BC\xc0\xdeEMBEDDED-LLVM-BITCODE")
	m := &image{machine: elf.EM_AARCH64, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 4, data: []byte{0xc0, 0x03, 0x5f, 0xd6}}, {name: ".llvmbc", typ: elf.SHT_PROGBITS, flags: elf.SectionFlag(0x80000000), align: 1, size: uint64(len(bitcode)), data: bitcode}, {name: ".llvmcmd", typ: elf.SHT_PROGBITS, flags: elf.SectionFlag(0x80000000), align: 1, size: 3, data: []byte("-O3")}, {name: ".debug_info", typ: elf.SHT_PROGBITS, align: 1, size: 5, data: []byte("DEBUG")}, {name: ".data", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8), relocs: []reloc{{off: 0, sym: 1, typ: elf.R_AARCH64(elf.R_AARCH64_ABS64)}}}}, symbols: []symbol{{}, {name: "native_fn", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 1, size: 4}, {name: "llvm.embedded.module", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_OBJECT), sect: 2, size: uint64(len(bitcode))}, {name: "source.c", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_FILE), sect: uint16(elf.SHN_ABS)}}}
	original, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(original)
	stripped, n, size, err := StripBitcode(original)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || size != uint64(len(bitcode)+3) || !bytes.Equal(original, before) || bytes.Contains(stripped, bitcode) {
		t.Fatalf("bitcode count %d/%d, payload remained or original was mutated", n, size)
	}
	f, err := elf.NewFile(bytes.NewReader(stripped))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Section(".llvmbc") != nil || f.Section(".llvmcmd") != nil || f.Section(".debug_info") == nil || f.Section(".data") == nil {
		t.Fatal("bitcode/debug/runtime section distinction lost")
	}
	if !bytes.Contains(stripped, []byte("source.c")) || bytes.Contains(stripped, []byte("llvm.embedded.module")) {
		t.Fatal("bitcode stripping changed non-bitcode symbols")
	}
	second, n, _, err := StripBitcode(stripped)
	if err != nil || n != 0 || !bytes.Equal(second, stripped) {
		t.Fatal("bitcode stripping is not idempotent", err)
	}
	m.sections[5].relocs[0].sym = 2
	live, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := StripBitcode(live); err == nil || !strings.Contains(err.Error(), "LLVM bitcode") {
		t.Fatal("runtime reference to bitcode was not rejected", err)
	}
}

func TestEncodeDropsEmptyLinkerOptions(t *testing.T) {
	m := tlsFixture()
	m.sections = append(m.sections, section{name: ".linker-options", typ: shtLLVMLinkerOptions, flags: 0x80000000, align: 1})
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	i := len(m.sections) - 1
	if len(f.Sections) <= i || f.Sections[i].Name != fmt.Sprintf(".bao.discard.%d", i) {
		t.Fatal("section indices were not preserved")
	}
	for _, s := range f.Sections {
		if s.Type == shtLLVMLinkerOptions || s.Name == ".linker-options" {
			t.Fatal("empty linker options section survived")
		}
	}
	for _, typ := range []elf.SectionType{shtLLVMLinkerOptions, shtLLVMDependentLibraries} {
		m := tlsFixture()
		m.sections = append(m.sections, section{name: ".deplibs", typ: typ, flags: 0x80000000, align: 1, size: 4, data: []byte("foo\x00")})
		if _, err := m.encode(); err == nil || !strings.Contains(err.Error(), "linker options") {
			t.Fatalf("non-empty %#x section was not rejected: %v", uint32(typ), err)
		}
	}
}
