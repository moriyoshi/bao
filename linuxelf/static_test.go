package linuxelf

import (
	"debug/elf"
	"testing"
)

// An archive's weak __cxa_pure_virtual reference must not silently pull a
// shared C++ runtime back into a build that bundled libstdc++.a.
func TestWeakImportDoesNotSelectSharedProvider(t *testing.T) {
	for _, machine := range []elf.Machine{elf.EM_AARCH64, elf.EM_X86_64, elf.EM_LOONGARCH, elf.EM_PPC64} {
		for _, strong := range []bool{false, true} {
			m := &image{machine: machine, sections: []section{{}}, symbols: []symbol{{}, {name: "optional", info: byte(elf.STB_WEAK) << 4}}}
			if strong {
				m.symbols = append(m.symbols, symbol{name: "required", info: byte(elf.STB_GLOBAL) << 4})
			}
			p := &Plan{Namespace: "test_"}
			if err := p.bind([]*image{m}, map[string]string{"optional": "libtest.so", "required": "libtest.so"}); err != nil {
				t.Fatalf("%s: %v", machine, err)
			}
			if strong {
				if len(p.Imports) != 2 || len(p.WeakZero) != 0 {
					t.Fatalf("%s: weak export of already required provider must bind: %+v", machine, p)
				}
			} else if len(p.Imports) != 0 || len(p.WeakZero) != 1 || p.WeakZero[0] != "optional" {
				t.Fatalf("%s: weak-only provider must remain NULL: %+v", machine, p)
			}
		}
	}
}

func TestUnwindProviderRequiredOnlyWithoutBundledRegistration(t *testing.T) {
	index := map[string]string{"optional": "libgcc_s.so.1"}
	m := &image{symbols: []symbol{{}, {name: "optional", info: byte(elf.STB_WEAK) << 4}}}
	p := &Plan{Unwind: []string{"frame"}}
	if !p.requiredLibraries([]*image{m}, index)["libgcc_s.so.1"] {
		t.Fatal("dynamic frame registration provider must be retained")
	}
	p.RegisterFrame = "__register_frame"
	if p.requiredLibraries([]*image{m}, index)["libgcc_s.so.1"] {
		t.Fatal("bundled frame registration must not select a DSO for a weak reference")
	}
}

func TestUniqueObjectKeepsIdentityAndRejectsOtherForms(t *testing.T) {
	s := symbol{name: "cpp_unique", sect: 1, value: 16, size: 8, info: 10<<4 | byte(elf.STT_OBJECT)}
	if err := normalizeUnique(&s); err != nil || elf.ST_BIND(s.info) != elf.STB_GLOBAL || s.sect != 1 || s.value != 16 || s.size != 8 {
		t.Fatal("coalesced object identity changed", s, err)
	}
	for _, s := range []symbol{{name: "undefined", info: 10<<4 | byte(elf.STT_OBJECT)}, {name: "function", sect: 1, info: 10<<4 | byte(elf.STT_FUNC)}} {
		if normalizeUnique(&s) == nil {
			t.Fatal("unmodeled unique symbol accepted", s)
		}
	}
}
