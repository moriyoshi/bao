package translate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"
)

func TestRuntimeTranslationRejectsUnregisteredImageSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, section, segment, message string
		flags                           uint32
	}{
		{"objc", "__objc_imageinfo", "__DATA", "image metadata", 0},
		{"swift", "__swift5_types", "__TEXT", "image metadata", 0},
		{"segment", "__payload", "__CUSTOM", "unsupported native segment", 0},
		{"init-offsets", "__init_offsets", "__TEXT", "unsupported native section type", 0x16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := fixture([]fixtureSection{{tc.section, tc.segment, tc.flags, make([]byte, 8), nil}}, nil)
			if _, err := readImage(o); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("image semantics silently discarded: %v", err)
			}
		})
	}
	for _, sym := range []macho.Symbol{
		{Name: "_common", Type: 1, Value: 16},
		{Name: "_absolute", Type: 3, Value: 42},
		{Name: "_bad_section", Type: 0xf, Sect: 2},
	} {
		o := fixture([]fixtureSection{{"__data", "__DATA", 0, make([]byte, 8), nil}}, []macho.Symbol{sym})
		if _, err := readImage(o); err == nil {
			t.Fatalf("unsupported symbol allocation/identity accepted: %+v", sym)
		}
	}
}

func TestLocalNameCollisionRequiresIndexedIdentity(t *testing.T) {
	o := fixture([]fixtureSection{{"__data", "__DATA", 0, make([]byte, 32), []macho.Reloc{
		{Addr: 16, Value: 0, Len: 3, Extern: true}, {Addr: 24, Value: 1, Len: 3, Extern: true},
	}}}, []macho.Symbol{{Name: "__MergedGlobals", Type: 0xe, Sect: 1}, {Name: "__MergedGlobals", Type: 0xe, Sect: 1, Value: 8}})
	r := reportFor(t, o)
	if r.Packable || !hasCode(r, "local-symbol-collision") {
		t.Fatal("unsafe name interning was accepted")
	}
	m, err := readImage(o)
	if err != nil {
		t.Fatal(err)
	}
	if n := m.uniquifyLocals("test_"); n != 2 {
		t.Fatal(n)
	}
	if m.symbols[0].Name == m.symbols[1].Name || m.symbols[0].Value != 0 || m.symbols[1].Value != 8 {
		t.Fatal("local identity/address lost")
	}
	if m.sections[0].relocs[0].Value != 0 || m.sections[0].relocs[1].Value != 1 {
		t.Fatal("indexed references collapsed")
	}
}

func TestStartupTextAlignmentPaddingPreservesAddresses(t *testing.T) {
	makeImage := func() *objectImage {
		return &objectImage{
			sections: []imageSection{
				{name: "__text", seg: "__TEXT", flags: 0x80000400, size: 3, data: []byte{1, 2, 3}},
				{name: "__StaticInit", seg: "__TEXT", flags: 0x80000400, addr: 16, size: 2, align: 4, data: []byte{4, 5}, relocs: []macho.Reloc{{Addr: 1, Value: 0, Extern: true}}},
				{name: "__const", seg: "__TEXT", addr: 18, size: 1, data: []byte{6}},
			},
			symbols: []macho.Symbol{{Name: "_fn", Sect: 1}, {Name: "_ctor", Sect: 2, Value: 16}, {Name: "_data", Sect: 3, Value: 18}},
		}
	}
	m := makeImage()
	if n, err := m.mergeExecutableText(); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if len(m.sections) != 2 || m.sections[0].size != 18 || m.sections[0].align != 4 || !bytes.Equal(m.sections[0].data, append(append([]byte{1, 2, 3}, make([]byte, 13)...), 4, 5)) {
		t.Fatalf("incorrect merged layout: %+v", m.sections)
	}
	if m.sections[0].relocs[0].Addr != 17 || m.symbols[1].Sect != 1 || m.symbols[1].Value != 16 || m.symbols[2].Sect != 2 || m.symbols[2].Value != 18 {
		t.Fatal("native relocation/symbol addresses changed")
	}
	for _, kind := range []string{"intervening-data", "non-alignment-gap", "overlap", "oversized-alignment"} {
		t.Run(kind, func(t *testing.T) {
			m := makeImage()
			switch kind {
			case "intervening-data":
				m.sections[2].addr = 8
			case "non-alignment-gap":
				m.sections[1].addr = 32
			case "overlap":
				m.sections[1].addr = 2
			case "oversized-alignment":
				m.sections[1].align = 64
			}
			if _, err := m.mergeExecutableText(); err == nil {
				t.Fatal("unsafe text merge accepted")
			}
		})
	}
}

func TestImplicitPointerAddendSurvivesELFConversion(t *testing.T) {
	ptr := make([]byte, 8)
	binary.LittleEndian.PutUint64(ptr, 7)
	o := fixture([]fixtureSection{
		{"__const", "__TEXT", 0, make([]byte, 16), nil},
		{"__data", "__DATA", 0, ptr, []macho.Reloc{{Value: 0, Len: 3, Extern: true}}},
	}, []macho.Symbol{{Name: "_bytes", Type: 0xf, Sect: 1}})
	if r := reportFor(t, o); r.Packable || !hasCode(r, "implicit-addend") {
		t.Fatal("embedded native addend was silently accepted")
	}
	p := TLSProbe{Objects: []Object{o}, Namespace: "test_"}
	if err := p.NormalizeAddends(); err != nil {
		t.Fatal(err)
	}
	m, err := readImage(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	if m.sections[1].relocs[0].Type != 10 || m.sections[1].relocs[0].Value != 7 || binary.LittleEndian.Uint64(m.sections[1].data) != 0 {
		t.Fatal("addend was lost or applied twice")
	}
	b, err := ELFContainer(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := f.Section(".rela.bao.1").Data()
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 24 || binary.LittleEndian.Uint64(r[16:]) != 7 || uint32(binary.LittleEndian.Uint64(r[8:])) != uint32(elf.R_AARCH64_ABS64) {
		t.Fatalf("ELF pointer relocation changed: %x", r)
	}
}

func TestFoldRelocatedCIEIdentifierAndPCExpression(t *testing.T) {
	eh := make([]byte, 56)
	binary.LittleEndian.PutUint32(eh, 16)
	copy(eh[8:], []byte{1, 'z', 'R', 0, 1, 0x78, 30, 1, 0, 0x0c, 31, 0})
	binary.LittleEndian.PutUint32(eh[20:], 32)
	binary.LittleEndian.PutUint32(eh[24:], 4)          // FDE - CIE + 4, before relocation
	binary.LittleEndian.PutUint64(eh[28:], ^uint64(7)) // func - FDE - 8
	o := fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, make([]byte, 16), nil},
		{"__eh_frame", "__TEXT", 0, eh, []macho.Reloc{
			{Addr: 24, Type: 1, Len: 2, Extern: true, Value: 1}, {Addr: 24, Len: 2, Extern: true, Value: 2},
			{Addr: 28, Type: 1, Len: 3, Extern: true, Value: 2}, {Addr: 28, Len: 3, Extern: true, Value: 0},
		}},
	}, []macho.Symbol{{Name: "_fn", Type: 0xf, Sect: 1}, {Name: "_cie", Type: 0xe, Sect: 2, Value: 16}, {Name: "_fde", Type: 0xe, Sect: 2, Value: 36}})
	p := TLSProbe{Objects: []Object{o}, Namespace: "test_"}
	if err := p.PrepareRuntimeMetadata(); err != nil {
		t.Fatal(err)
	}
	if len(p.Unwind) != 1 || len(p.Unwind[0].FDEOffsets) != 1 || p.Unwind[0].FDEOffsets[0] != 20 {
		t.Fatalf("FDE parsing failed: %+v", p.Unwind)
	}
	if err := p.NormalizeAddends(); err != nil {
		t.Fatal(err)
	}
	b, err := ELFContainer(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rel, err := f.Section(".rela.bao.1").Data()
	if err != nil {
		t.Fatal(err)
	}
	// The final expression is func - address-of-field. No residual offset.
	if len(rel) != 24 || binary.LittleEndian.Uint64(rel) != 28 || uint32(binary.LittleEndian.Uint64(rel[8:])) != uint32(elf.R_AARCH64_PREL64) || binary.LittleEndian.Uint64(rel[16:]) != 0 {
		t.Fatalf("incorrect PC-relative FDE expression: %x", rel)
	}
}

func TestCompactFramesPreserveCalleeSavedRegisters(t *testing.T) {
	for _, tc := range []struct {
		encoding uint32
		expected []byte
	}{
		{0x04000003, []byte{0x0c, 29, 16, 0x9d, 2, 0x9e, 1, 0x93, 3, 0x94, 4, 0x95, 5, 0x96, 6}},
		{0x02004001, []byte{0x0c, 31, 64, 0x93, 1, 0x94, 2}},
	} {
		cu := make([]byte, 32)
		binary.LittleEndian.PutUint32(cu[8:], 64)
		binary.LittleEndian.PutUint32(cu[12:], tc.encoding)
		o := fixture([]fixtureSection{{"__text", "__TEXT", 0x80000400, make([]byte, 64), nil}, {"__compact_unwind", "__LD", 0x02000000, cu, []macho.Reloc{{Len: 3, Extern: true}}}}, []macho.Symbol{{Name: "_fn", Type: 0xf, Sect: 1}})
		m, err := readImage(o)
		if err != nil {
			t.Fatal(err)
		}
		section, n, err := m.synthesizeCompactFrames("test_", 0)
		if err != nil || n != 1 {
			t.Fatalf("synthesize: %d %v", n, err)
		}
		data := m.sections[len(m.sections)-1].data
		if !bytes.Contains(data, tc.expected) {
			t.Fatalf("incorrect CFI for %#x: %x", tc.encoding, data)
		}
		offsets, err := frameOffsets(data)
		if err != nil || len(offsets) != 1 || offsets[0] != section.FDEOffsets[0] {
			t.Fatalf("malformed synthetic FDE: %v %v", offsets, err)
		}
		// Original native metadata is still available and was not rewritten.
		if !bytes.Equal(m.sections[1].data, cu) {
			t.Fatal("original compact metadata changed")
		}
	}
}

func TestELFContainerPropagatesNativeSectionAlignment(t *testing.T) {
	o := leafFixture()
	m, err := readImage(o)
	if err != nil {
		t.Fatal(err)
	}
	m.sections[0].align = 6
	m.sections = append(m.sections, imageSection{name: "__data", seg: "__DATA", addr: 128, size: 128, align: 7, data: make([]byte, 128)})
	m.symbols = append(m.symbols, macho.Symbol{Name: "_aligned", Type: 0xf, Sect: 2, Value: 128})
	o.Data, err = m.encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ELFContainer(o)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Machine != elf.EM_AARCH64 || f.Type != elf.ET_REL || f.Sections[1].Addralign != 64 || f.Sections[2].Addralign != 128 {
		t.Fatal("native alignment/container changed")
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	if symbols[0].Name != "leaf" || symbols[1].Name != "aligned" || symbols[1].Value != 0 {
		t.Fatalf("wrong Go ELF symbol convention: %+v", symbols)
	}
}

func TestSDKIndexFiltersArchitectureAndKeepsUmbrellaLibrary(t *testing.T) {
	input := []byte(`--- !tapi-tbd
tbd-version: 4
targets: [ arm64e-macos, x86_64-macos ]
install-name: '/usr/lib/libSystem.B.dylib'
exports:
  - targets: [ x86_64-macos ]
    symbols: [ _wrong_arch ]
  - targets: [ arm64e-macos ]
    symbols: [ '_first', _second ]
    weak-symbols: [ _weak ]
--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/system/libsystem_c.dylib'
exports:
  - targets: [ arm64-macos ]
    symbols: [ _child ]
`)
	lib, symbols, err := tbdSymbols(input)
	if err != nil {
		t.Fatal(err)
	}
	if lib != "/usr/lib/libSystem.B.dylib" || len(symbols) != 4 {
		t.Fatalf("wrong SDK exports: %s %v", lib, symbols)
	}
	for _, s := range symbols {
		if s == "_wrong_arch" {
			t.Fatal("x86-only symbol accepted")
		}
	}
}

func TestSystemBranchesUseNativeTailBridgesAndDataKeepsRealAddress(t *testing.T) {
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code, 0x94000000)
	binary.LittleEndian.PutUint32(code[4:], 0xd65f03c0)
	ptr := make([]byte, 8)
	binary.LittleEndian.PutUint64(ptr, 7)
	o := fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, code, []macho.Reloc{{Type: 2, Len: 2, Extern: true, Pcrel: true}}},
		{"__data", "__DATA", 0, ptr, []macho.Reloc{{Len: 3, Extern: true}}},
	}, []macho.Symbol{{Name: "_foreign", Type: 1}, {Name: "_entry", Type: 0xf, Sect: 1}})
	p := TLSProbe{Objects: []Object{o}, Namespace: "test_"}
	if err := p.bindSystemImports(map[string]string{"_foreign": "/usr/lib/libSystem.B.dylib"}); err != nil {
		t.Fatal(err)
	}
	if len(p.Imports) != 1 || p.Imports[0].CallSymbol != "test_import_0_call" || len(p.Fixups) != 1 || p.Fixups[0].ImportLocal != "test_import_0" || p.Fixups[0].Addend != 7 {
		t.Fatalf("incorrect bridge/fixup plan: %+v", p)
	}
	m, err := readImage(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	target := m.symbols[m.sections[0].relocs[0].Value]
	if target.Name != "_test_import_0_call" || len(m.sections[1].relocs) != 0 || binary.LittleEndian.Uint64(m.sections[1].data) != 0 {
		t.Fatal("native call bridge or dynamic data address was misbound")
	}
}
