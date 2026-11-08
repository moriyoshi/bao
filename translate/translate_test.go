package translate

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"testing"
)

// A small independent Mach-O fixture builder. Section layout, symbol references,
// and TLVP instruction encodings are explicit; no host compiler is needed.
type fixtureSection struct {
	name, seg string
	flags     uint32
	data      []byte
	relocs    []macho.Reloc
}

func fixture(sections []fixtureSection, symbols []macho.Symbol) Object {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	cmdsize := 72 + 80*len(sections) + 24
	w([8]uint32{macho.Magic64, uint32(macho.CpuArm64), 0, uint32(macho.TypeObj), 2, uint32(cmdsize), 0, 0})
	dataStart := 32 + cmdsize
	dataSize, relocSize := 0, 0
	for _, s := range sections {
		dataSize += len(s.data)
		relocSize += len(s.relocs) * 8
	}
	w([2]uint32{25, uint32(72 + 80*len(sections))})
	w([16]byte{})
	w([4]uint64{0, uint64(dataSize), uint64(dataStart), uint64(dataSize)})
	w([4]uint32{7, 7, uint32(len(sections)), 0})
	addr, relocOff := 0, dataStart+dataSize
	for _, s := range sections {
		var name, seg [16]byte
		copy(name[:], s.name)
		copy(seg[:], s.seg)
		w(name)
		w(seg)
		w([2]uint64{uint64(addr), uint64(len(s.data))})
		w([8]uint32{uint32(dataStart + addr), 2, uint32(relocOff), uint32(len(s.relocs)), s.flags, 0, 0, 0})
		addr += len(s.data)
		relocOff += len(s.relocs) * 8
	}
	strtab := []byte{0}
	indices := make([]uint32, len(symbols))
	for i, sym := range symbols {
		indices[i] = uint32(len(strtab))
		strtab = append(strtab, sym.Name...)
		strtab = append(strtab, 0)
	}
	symoff := dataStart + dataSize + relocSize
	w([6]uint32{2, 24, uint32(symoff), uint32(len(symbols)), uint32(symoff + 16*len(symbols)), uint32(len(strtab))})
	for _, s := range sections {
		b.Write(s.data)
	}
	for _, s := range sections {
		for _, r := range s.relocs {
			v := r.Value | uint32(r.Len)<<25 | uint32(r.Type)<<28
			if r.Pcrel {
				v |= 1 << 24
			}
			if r.Extern {
				v |= 1 << 27
			}
			w([2]uint32{r.Addr, v})
		}
	}
	for i, sym := range symbols {
		w(indices[i])
		w(sym.Type)
		w(sym.Sect)
		w(sym.Desc)
		w(sym.Value)
	}
	b.Write(strtab)
	return Object{Name: "fixture.o", Data: b.Bytes()}
}

func leafFixture() Object {
	return fixture([]fixtureSection{{"__text", "__TEXT", 0x80000400, []byte{0xc0, 3, 0x5f, 0xd6}, nil}}, []macho.Symbol{{Name: "_leaf", Type: 0xf, Sect: 1}})
}

func tlsFixture() Object {
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code, 0x90000000)     // adrp x0, descriptor@TLVPPAGE
	binary.LittleEndian.PutUint32(code[4:], 0xf9400000) // ldr x0, [x0, descriptor@TLVPPAGEOFF]
	return fixture([]fixtureSection{
		{"__text", "__TEXT", 0x80000400, code, []macho.Reloc{
			{Addr: 4, Value: 1, Type: 9, Len: 2, Extern: true},
			{Addr: 0, Value: 1, Type: 8, Len: 2, Pcrel: true, Extern: true},
		}},
		{"__thread_vars", "__DATA", 0x13, make([]byte, 24), nil},
	}, []macho.Symbol{{Name: "_tls", Type: 0xf, Sect: 1}, {Name: "_descriptor", Type: 0xf, Sect: 2, Value: 8}})
}

func reportFor(t *testing.T, o Object) Report {
	t.Helper()
	r, err := Inspect(o.Data, []Object{o})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasCode(r Report, code string) bool {
	for _, o := range r.Objects {
		for _, f := range o.Findings {
			if f.Code == code {
				return true
			}
		}
	}
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestLeafAndSemanticBlockers(t *testing.T) {
	if r := reportFor(t, leafFixture()); !r.Packable {
		t.Fatalf("leaf rejected: %+v", r)
	}
	for _, tc := range []struct {
		name, seg string
		flags     uint32
		code      string
	}{
		{"__eh_frame", "__TEXT", 0, "unwind-metadata"},
		{"__compact_unwind", "__LD", 0x02000000, "unwind-metadata"},
		{"__mod_init_func", "__DATA", 9, "initializers"},
		{"__thread_bss", "__DATA", 0x12, "tls-lifecycle"},
		{"__objc_classlist", "__DATA", 0, "objc-metadata"},
		{"__const", "__DATA_CONST", 0, "ignored-section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := fixture([]fixtureSection{{tc.name, tc.seg, tc.flags, make([]byte, 8), nil}}, []macho.Symbol{{Name: "_data", Type: 0xf, Sect: 1}})
			r := reportFor(t, o)
			if r.Packable || !hasCode(r, tc.code) {
				t.Fatalf("missing semantic blocker %s: %+v", tc.code, r)
			}
		})
	}
}

func TestLoweringPreservesTLSAndOnlyChangesRelocationTypes(t *testing.T) {
	o := tlsFixture()
	before := bytes.Clone(o.Data)
	r := reportFor(t, o)
	if r.Packable || !hasCode(r, "tlvp-relocation") || !hasCode(r, "tls-lifecycle") {
		t.Fatalf("bad before report: %+v", r)
	}
	out, n, err := LowerTLVP(o)
	if err != nil || n != 2 {
		t.Fatalf("lower: %d %v", n, err)
	}
	if !bytes.Equal(o.Data, before) {
		t.Fatal("mutated input")
	}
	f, _ := openObject(o)
	defer f.Close()
	// Validate the entire file, including TLS data and symbol names. Only the
	// relocation type nibbles may change, so destructive TLS stripping fails.
	expect := bytes.Clone(before)
	for i, typ := range []byte{6, 5} {
		pos := int(f.Sections[0].Reloff) + i*8 + 7
		expect[pos] = expect[pos]&15 | typ<<4
	}
	if !bytes.Equal(expect, out) {
		t.Fatal("lowering changed data outside the relocation type fields")
	}
	post := reportFor(t, Object{Name: o.Name, Data: out})
	if post.Packable || hasCode(post, "tlvp-relocation") || !hasCode(post, "tls-lifecycle") {
		t.Fatalf("lowering incorrectly certified TLS runtime: %+v", post)
	}
}

func TestLowerRejectsUnexpectedInstructionAndNonlocalDescriptor(t *testing.T) {
	for _, mode := range []string{"opcode", "undefined", "not-descriptor", "pcrel"} {
		t.Run(mode, func(t *testing.T) {
			o := tlsFixture()
			f, _ := openObject(o)
			defer f.Close()
			s := f.Sections[0]
			// debug/macho exposes the parsed symbols but does not populate
			// SymtabCmd. Read the original load command for the file offset.
			sympos := int(binary.LittleEndian.Uint32(f.Symtab.Raw()[8:])) + 16
			switch mode {
			case "opcode":
				binary.LittleEndian.PutUint32(o.Data[s.Offset+4:], 0xd503201f) // nop, not ldr
			case "undefined":
				o.Data[sympos+5] = 0
			case "not-descriptor":
				o.Data[sympos+5] = 1
			case "pcrel":
				o.Data[s.Reloff+7] |= 1
			}
			if _, _, err := LowerTLVP(o); err == nil {
				t.Fatal("accepted unsupported TLVP")
			}
		})
	}
}

func TestArchiveWideResolutionAndDenseFunctions(t *testing.T) {
	a := leafFixture()
	b := fixture([]fixtureSection{{"__data", "__DATA", 0, make([]byte, 8), []macho.Reloc{{Type: 0, Len: 3, Extern: true}}}}, []macho.Symbol{{Name: "_leaf", Type: 1}, {Name: "_ptr", Type: 0xf, Sect: 1}})
	input := append(bytes.Clone(a.Data), b.Data...)
	r, err := Inspect(input, []Object{a, b})
	if err != nil || !r.Packable || len(r.Unresolved) != 0 {
		t.Fatalf("cross-object resolution failed: %+v %v", r, err)
	}
	r = reportFor(t, b)
	if r.Packable || !hasCode(r, "unresolved-symbols") {
		t.Fatal("missing unresolved symbol blocker")
	}
	var syms []macho.Symbol
	for i := range 260 {
		syms = append(syms, macho.Symbol{Name: fmt.Sprintf("_tiny_%d", i), Type: 0xf, Sect: 1, Value: uint64(4 * i)})
	}
	o := fixture([]fixtureSection{{"__text", "__TEXT", 0x80000400, make([]byte, 4096), nil}}, syms)
	if r := reportFor(t, o); r.Packable || !hasCode(r, "function-density") {
		t.Fatal("missing Go findfunc overflow blocker")
	}
}
