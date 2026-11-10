package translate

import (
	"bytes"
	"debug/macho"
	"strings"
	"testing"
)

func TestStripNativeDebugKeepsUnwindAndIndexedIdentity(t *testing.T) {
	o := fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, make([]byte, 8), []macho.Reloc{{Value: 2, Extern: true, Len: 3}}},
		{"__debug_info", "__DWARF", 0, make([]byte, 16), []macho.Reloc{{Value: 0, Type: 15, Extern: true, Len: 3}}},
		{"__data", "__DATA", 0, make([]byte, 8), nil},
		{"__eh_frame", "__TEXT", 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}, nil},
	}, []macho.Symbol{{Name: "_code", Type: 0xf, Sect: 1}, {Name: "_debug", Type: 0xe, Sect: 2, Value: 8}, {Name: "_data", Type: 0xf, Sect: 3, Value: 24}})
	original := bytes.Clone(o.Data)
	b, n, err := StripDebug(o.Data)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !bytes.Equal(original, o.Data) {
		t.Fatal("strip count or input mutation")
	}
	m, err := readImage(Object{Name: "stripped.o", Data: b})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sections) != 3 || len(m.symbols) != 2 || m.symbols[1].Sect != 2 || m.symbols[1].Value != 24 || m.sections[0].relocs[0].Value != 1 {
		t.Fatal("native indexed references were not remapped")
	}
	if m.sections[2].name != "__eh_frame" || !bytes.Equal(m.sections[2].data, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("runtime unwind data changed")
	}
	b2, n, err := StripDebug(b)
	if err != nil || n != 0 || !bytes.Equal(b, b2) {
		t.Fatalf("strip not idempotent: %v", err)
	}
}

func TestStripBitcodeDropsLLVMSegmentOnly(t *testing.T) {
	bitcode := append([]byte{0xde, 0xc0, 0x17, 0x0b}, bytes.Repeat([]byte("BC"), 14)...)
	o := fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, make([]byte, 8), []macho.Reloc{{Value: 3, Extern: true, Len: 3}}},
		{"__bitcode", "__LLVM", 0, bitcode, nil},
		{"__cmdline", "__LLVM", 0, []byte{0, 0, 0, 0}, nil},
		{"__debug_info", "__DWARF", 0, make([]byte, 8), nil},
		{"__data", "__DATA", 0, make([]byte, 8), nil},
	}, []macho.Symbol{{Name: "_code", Type: 0xf, Sect: 1}, {Name: "ltmp1", Type: 0xe, Sect: 2, Value: 8}, {Name: "ltmp2", Type: 0xe, Sect: 3, Value: 40}, {Name: "_data", Type: 0xf, Sect: 5, Value: 52}})
	original := bytes.Clone(o.Data)
	b, n, size, err := StripBitcode(o.Data)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || size != uint64(len(bitcode)+4) || !bytes.Equal(original, o.Data) || bytes.Contains(b, bitcode) {
		t.Fatalf("strip count %d/%d, input mutation or bitcode payload remained", n, size)
	}
	m, err := readImage(Object{Name: "stripped.o", Data: b})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sections) != 3 || m.sections[1].seg != "__DWARF" || len(m.symbols) != 2 || m.symbols[1].Sect != 3 || m.sections[0].relocs[0].Value != 1 {
		t.Fatal("debug or runtime references were not preserved and remapped")
	}
	b2, n, size, err := StripBitcode(b)
	if err != nil || n != 0 || size != 0 || !bytes.Equal(b, b2) {
		t.Fatalf("strip not idempotent: %v", err)
	}
}

func TestStripBitcodeRejectsLiveReference(t *testing.T) {
	for _, r := range []macho.Reloc{{Value: 1, Extern: true, Len: 3}, {Value: 2, Len: 3}} {
		o := fixture([]fixtureSection{
			{"__text", "__TEXT", 0x80000400, make([]byte, 8), nil},
			{"__bitcode", "__LLVM", 0, make([]byte, 8), nil},
			{"__data", "__DATA", 0, make([]byte, 8), []macho.Reloc{r}},
		}, []macho.Symbol{{Name: "_code", Type: 0xf, Sect: 1}, {Name: "_embedded", Type: 0xe, Sect: 2, Value: 8}})
		if _, _, _, err := StripBitcode(o.Data); err == nil || !strings.Contains(err.Error(), "LLVM bitcode") {
			t.Fatalf("live reference to bitcode was not rejected: %v", err)
		}
	}
}
