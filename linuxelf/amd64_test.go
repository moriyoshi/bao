package linuxelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

func amd64TLSFixture(ld bool) (*image, *Plan) {
	p := &Plan{Namespace: "amd_"}
	code := []byte{0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0, 0, 0, 0}
	typ := elf.R_X86_64_TLSGD
	if ld {
		typ = elf.R_X86_64_TLSLD
	}
	m := &image{machine: elf.EM_X86_64, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 16, size: uint64(len(code)), data: code, relocs: []reloc{{off: 3, sym: 1, typ: elf.R_AARCH64(typ), add: -4}, {off: 8, sym: 2, typ: elf.R_AARCH64(elf.R_X86_64_PLT32), add: -4}, {off: 15, sym: 1, typ: elf.R_AARCH64(elf.R_X86_64_DTPOFF32)}}}, {name: ".tdata", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_TLS | elf.SHF_WRITE, align: 128, size: 16, data: make([]byte, 16)}}, symbols: []symbol{{}, {name: "tls", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_TLS), sect: 2, value: 8, size: 8}, {name: p.Runtime("tls_lookup"), info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)}}}
	return m, p
}

func TestAMD64DynamicTLSIsDirectDescriptorNotGoTLS(t *testing.T) {
	for _, ld := range []bool{false, true} {
		m, p := amd64TLSFixture(ld)
		before := bytes.Clone(m.sections[1].data[:15])
		if err := p.lowerTLSForMachine(m); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, m.sections[1].data[:15]) || len(m.sections[1].relocs) != 2 || elf.R_X86_64(m.sections[1].relocs[0].typ) != elf.R_X86_64_PC32 || m.sections[1].relocs[0].add != -4 {
			t.Fatal("GD/LD lowering changed instructions, retained native TLS relocations, or lost RIP bias")
		}
		if binary.LittleEndian.Uint32(m.sections[1].data[15:]) != 8 || p.TLSTemplateAlignment != 128 || p.TLSDescriptors != 1 {
			t.Fatal("local-dynamic offset/template layout")
		}
		desc := m.sections[len(m.sections)-1]
		want := uint64(8)
		if ld {
			want = 0
		}
		if binary.LittleEndian.Uint64(desc.data[8:]) != want {
			t.Fatal("GD must return symbol pointer; LD must return module base")
		}
	}
}

func TestAMD64TLSRejectsUnmodeledSequences(t *testing.T) {
	for _, kind := range []string{"lea-register", "rip-bias", "wrong-call", "call-prefix", "initial-exec", "local-exec", "gnu2-desc", "offset-overflow", "symbol-wrap"} {
		t.Run(kind, func(t *testing.T) {
			m, p := amd64TLSFixture(true)
			s := &m.sections[1]
			switch kind {
			case "lea-register":
				s.data[2] = 0x35 // RSI instead of descriptor argument RDI.
			case "rip-bias":
				s.relocs[0].add = 0
			case "wrong-call":
				s.relocs[1].sym = 1
			case "call-prefix":
				s.data[7] = 0x90
			case "initial-exec":
				s.relocs[0].typ = elf.R_AARCH64(elf.R_X86_64_GOTTPOFF)
			case "local-exec":
				s.relocs[0].typ = elf.R_AARCH64(elf.R_X86_64_TPOFF32)
			case "gnu2-desc":
				s.relocs[0].typ = elf.R_AARCH64(elf.R_X86_64_GOTPC32_TLSDESC)
			case "offset-overflow":
				s.relocs[2].add = 256
			case "symbol-wrap":
				m.sections = append(m.sections, section{name: ".tbss", typ: elf.SHT_NOBITS, flags: elf.SHF_ALLOC | elf.SHF_TLS | elf.SHF_WRITE, align: 128, size: 8})
				m.symbols[1].sect, m.symbols[1].value = 3, ^uint64(0)-127
			}
			if err := p.lowerTLSForMachine(m); err == nil {
				t.Fatal("unsupported TLS form accepted")
			}
		})
	}
}

func TestAMD64StrongImportOverridesOtherImageWeak(t *testing.T) {
	weak := &image{machine: elf.EM_X86_64, sections: []section{{}}, symbols: []symbol{{}, {name: "required", info: byte(elf.STB_WEAK) << 4}}}
	strong := &image{machine: elf.EM_X86_64, sections: []section{{}}, symbols: []symbol{{}, {name: "required", info: byte(elf.STB_GLOBAL) << 4}}}
	if err := (&Plan{}).bindAMD64([]*image{weak, strong}, nil); err == nil {
		t.Fatal("one image's weak declaration hid another image's required import")
	}
	for _, add := range []int64{0, 1, -3} {
		m := &image{machine: elf.EM_X86_64, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 16, size: 7, data: []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0}, relocs: []reloc{{off: 3, sym: 1, typ: elf.R_AARCH64(elf.R_X86_64_GOTPCREL), add: add}}}}, symbols: []symbol{{}, {name: "optional", info: byte(elf.STB_WEAK) << 4}}}
		if err := (&Plan{}).bindAMD64([]*image{m}, nil); err == nil {
			t.Fatalf("missing weak GOT addend %d accepted; only the -4 RIP bias is modeled", add)
		}
	}
}

func TestAMD64ImportedPointersAndWeakNull(t *testing.T) {
	m := &image{machine: elf.EM_X86_64, sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 16, size: 7, data: []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0}, relocs: []reloc{{off: 3, sym: 2, typ: elf.R_AARCH64(elf.R_X86_64_REX_GOTPCRELX), add: -4}}}, {name: ".data.rel", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8), relocs: []reloc{{sym: 1, typ: elf.R_AARCH64(elf.R_X86_64_64), add: 7}}}}, symbols: []symbol{{}, {name: "environ", info: byte(elf.STB_GLOBAL) << 4}, {name: "optional", info: byte(elf.STB_WEAK) << 4}}}
	p := &Plan{Namespace: "amd_"}
	if err := p.bindAMD64([]*image{m}, map[string]string{"environ": "libc.so.6"}); err != nil {
		t.Fatal(err)
	}
	if len(p.Fixups) != 1 || p.Fixups[0].Addend != 7 || len(m.sections[2].relocs) != 0 {
		t.Fatal("dynamic ABS64 pointer not lowered to checked data fixup")
	}
	if m.sections[1].data[1] != 0x8b || elf.R_X86_64(m.sections[1].relocs[0].typ) != elf.R_X86_64_PC32 {
		t.Fatal("missing weak GOT load must read NULL cell, not relax to its address")
	}
	if len(p.WeakZero) != 1 || p.WeakZero[0] != "optional" {
		t.Fatal("weak import contract lost")
	}
}

func TestAMD64LLVMUnwindSectionTypeIsNarrow(t *testing.T) {
	good := section{name: ".eh_frame", typ: elf.SectionType(0x70000001), flags: elf.SHF_ALLOC, align: 8, size: 8, data: []byte{4, 0, 0, 0, 0, 0, 0, 0}}
	copy := good
	if err := normalizeAMD64Unwind(&copy); err != nil || copy.typ != elf.SHT_PROGBITS || !bytes.Equal(copy.data, good.data) {
		t.Fatal("ordinary LLVM EH frame was not preserved", err)
	}
	for _, kind := range []string{"other-type", "other-name", "execute", "tls", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			s := good
			switch kind {
			case "other-type":
				s.typ++
			case "other-name":
				s.name = ".other"
			case "execute":
				s.flags |= elf.SHF_EXECINSTR
			case "tls":
				s.flags |= elf.SHF_TLS
			case "truncated":
				s.data = s.data[:6]
			}
			if normalizeAMD64Unwind(&s) == nil {
				t.Fatal("unmodeled processor-specific section accepted")
			}
		})
	}
}
