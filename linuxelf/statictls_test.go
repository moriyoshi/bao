package linuxelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

func TestStaticTLSStub(t *testing.T) {
	for arch, want := range staticTLSMachines {
		m, err := StaticTLSStub(arch, 40, 64)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Prefix)%64 != 0 {
			t.Fatalf("%s: template at %d is not aligned", arch, len(m.Prefix))
		}
		image := append(m.Prefix, bytes.Repeat([]byte{0xa5}, 40)...)
		f, err := elf.NewFile(bytes.NewReader(image))
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if f.Type != elf.ET_DYN || f.Machine != want.machine {
			t.Fatalf("%s: type %s machine %s", arch, f.Type, f.Machine)
		}
		var tls, stack *elf.Prog
		dyn := map[elf.DynTag]uint64{}
		for _, p := range f.Progs {
			switch p.Type {
			case elf.PT_DYNAMIC:
				// The stub has no section headers, which debug/elf's DynValue needs.
				for d := image[p.Off : p.Off+p.Filesz]; len(d) >= 16; d = d[16:] {
					dyn[elf.DynTag(binary.LittleEndian.Uint64(d))] = binary.LittleEndian.Uint64(d[8:])
				}
			case elf.PT_TLS:
				tls = p
			case elf.PT_GNU_STACK:
				stack = p
			case elf.PT_LOAD:
				if p.Off != 0 || p.Filesz != uint64(len(image)) || p.Flags&elf.PF_X != 0 {
					t.Fatalf("%s: load segment %+v", arch, p.ProgHeader)
				}
			}
		}
		if tls == nil || tls.Off != uint64(len(m.Prefix)) || tls.Filesz != 40 || tls.Memsz != 40 || tls.Align != 64 {
			t.Fatalf("%s: TLS segment %+v", arch, tls)
		}
		if stack == nil || stack.Flags&elf.PF_X != 0 {
			t.Fatalf("%s: stack segment %+v", arch, stack)
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_DYNAMIC && p.Vaddr != m.Dynamic {
				t.Fatalf("%s: dynamic table at %#x, recorded %#x", arch, p.Vaddr, m.Dynamic)
			}
		}
		if dyn[elf.DT_FLAGS] != uint64(elf.DF_STATIC_TLS) || dyn[elf.DT_RELASZ] != 24 || dyn[elf.DT_SYMTAB] == 0 {
			t.Fatalf("%s: dynamic table %v", arch, dyn)
		}
		r := image[dyn[elf.DT_RELA]:]
		if binary.LittleEndian.Uint64(r) != m.OffsetWord || binary.LittleEndian.Uint64(r[8:]) != uint64(want.tprel) || binary.LittleEndian.Uint64(r[16:]) != 0 {
			t.Fatalf("%s: relocation % x", arch, r[:24])
		}
	}
	for _, c := range []struct {
		arch        string
		size, align uint64
		err         string
	}{{"riscv64", 8, 8, "unsupported"}, {"arm64", 0, 8, "nonempty"}, {"arm64", 8, 24, "power of two"}, {"arm64", 8, 8192, "up to 4096"}} {
		if _, err := StaticTLSStub(c.arch, c.size, c.align); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Fatalf("StaticTLSStub(%s, %d, %d) = %v", c.arch, c.size, c.align, err)
		}
	}
}
