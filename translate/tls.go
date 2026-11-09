package translate

import (
	"debug/macho"
	_ "embed"
	"encoding/binary"
	"fmt"
	"strings"
)

// Built from the adjacent, original Apache-2.0 sources. Maintainers regenerate
// these using bazel run //:native; neither translator nor consumer invokes C.
//
//go:embed native/tls.bin
var tlsRuntime []byte

//go:embed native/thunk.bin
var tlsThunk []byte

//go:embed native/amd64/tls.bin
var tlsRuntimeAMD64 []byte

//go:embed native/amd64/thunk.bin
var tlsThunkAMD64 []byte

type TLSProbe struct {
	Arch                            string
	Objects                         []Object
	Namespace                       string
	TemplateSymbol                  string
	TemplateSize, TemplateAlignment uint64
	Descriptors, Relocations        int
	AliasesRemoved, BoundarySymbols int
	TextSectionsMerged              int
	LocalSymbolsRenamed             int
	Imports                         []ImportBinding
	Fixups                          []PointerFixup
	Unwind                          []UnwindSection
	Constructors                    []ConstructorTable
	AddendsNormalized               int
	CompactFramesSynthesized        int
	RegisterFrame                   string
}

func (p TLSProbe) RuntimeSymbol(suffix string) string { return p.Namespace + suffix }

// LowerTLS is experimental. It implements TLS storage/descriptors/lifetime for
// one already-combined image. It does NOT implement native unwind registration,
// constructors or framework imports; those are separate pipeline stages. It also
// preserves indexed local identity and coalesces identical-address text aliases.
func LowerTLS(o Object) (TLSProbe, error) {
	return LowerTLSKeeping(o, nil)
}

func LowerTLSKeeping(o Object, keepSymbols []string) (TLSProbe, error) {
	var result TLSProbe
	lowered, n, err := LowerTLVP(o)
	if err != nil {
		return result, err
	}
	m, err := readImage(Object{Name: o.Name, Data: lowered})
	if err != nil {
		return result, err
	}
	result.Arch = "arm64"
	if m.cpu == macho.CpuAmd64 {
		result.Arch = "amd64"
	}
	result.Namespace = "bao_" + digest(o.Data)[:16] + "_"
	result.TemplateSymbol = result.Namespace + "tls_template"
	result.Relocations = n
	var base, end uint64
	base = ^uint64(0)
	align := uint64(8)
	templateSections := make(map[uint8]bool)
	for i, s := range m.sections {
		switch s.flags & 0xff {
		case 0x11, 0x12:
			templateSections[uint8(i+1)] = true
			if len(s.relocs) != 0 {
				return result, fmt.Errorf("relocations within TLS templates are not implemented")
			}
			base = min(base, s.addr)
			end = max(end, s.addr+s.size)
			align = max(align, uint64(1)<<s.align)
		case 0x14, 0x15:
			return result, fmt.Errorf("thread-local pointer/init function sections are not implemented")
		}
	}
	if base == ^uint64(0) {
		base, end = 0, 8
	} // TLS-free C/no_std libraries still need runtime import/unwind setup.
	if end <= base || end-base > 64<<20 {
		return result, fmt.Errorf("missing/oversized TLS template")
	}
	// Preserve alignment relative to the original virtual addresses, including
	// when a later template section needs stronger alignment than the first.
	base &^= align - 1
	template := make([]byte, end-base)
	for _, s := range m.sections {
		if s.flags&0xff == 0x11 {
			copy(template[s.addr-base:], s.data)
		}
	}
	for i := range m.symbols {
		s := &m.symbols[i]
		if s.Sect == 0 && (s.Name == "__tlv_bootstrap" || s.Name == "__tlv_atexit") {
			if s.Name == "__tlv_bootstrap" {
				s.Name = "_" + result.RuntimeSymbol("tls_thunk")
			} else {
				s.Name = "_" + result.RuntimeSymbol("tls_atexit")
			}
		}
	}
	for i := range m.sections {
		s := &m.sections[i]
		switch s.flags & 0xff {
		case 0x11:
			s.flags &^= 0xff // native template bytes remain ordinary data
		case 0x12:
			s.flags = (s.flags &^ 0xff) | 1 // preserve zero-fill as ordinary zero-fill
		case 0x13:
			if s.size%24 != 0 {
				return result, fmt.Errorf("TLS descriptor section size is not a multiple of 24")
			}
			byAddr := make(map[uint32]macho.Reloc)
			for _, r := range s.relocs {
				if _, ok := byAddr[r.Addr]; ok {
					return result, fmt.Errorf("overlapping TLS descriptor relocations")
				}
				if r.Type != 0 || r.Pcrel || r.Len != 3 || !r.Extern || int(r.Value) >= len(m.symbols) || uint64(r.Addr)+8 > s.size {
					return result, fmt.Errorf("unsupported TLS descriptor relocation")
				}
				byAddr[r.Addr] = r
			}
			var rels []macho.Reloc
			for at := uint32(0); uint64(at) < s.size; at += 24 {
				thunk, ok := byAddr[at]
				if !ok || m.symbols[thunk.Value].Name != "_"+result.RuntimeSymbol("tls_thunk") || binary.LittleEndian.Uint64(s.data[at:]) != 0 || binary.LittleEndian.Uint64(s.data[at+8:]) != 0 {
					return result, fmt.Errorf("unexpected preinitialized TLS descriptor at %#x", at)
				}
				init, ok := byAddr[at+16]
				if !ok {
					return result, fmt.Errorf("TLS descriptor has no template reference")
				}
				target := m.symbols[init.Value]
				if target.Sect == 0 || int(target.Sect) > len(m.sections) {
					return result, fmt.Errorf("TLS descriptor template is undefined")
				}
				t := m.sections[target.Sect-1]
				if !templateSections[target.Sect] || target.Value < t.addr || target.Value >= t.addr+t.size {
					return result, fmt.Errorf("TLS descriptor targets a non-template section")
				}
				offset := target.Value + binary.LittleEndian.Uint64(s.data[at+16:]) - base
				if offset >= uint64(len(template)) {
					return result, fmt.Errorf("TLS descriptor offset outside template")
				}
				binary.LittleEndian.PutUint64(s.data[at+16:], offset)
				rels = append(rels, thunk)
				delete(byAddr, at)
				delete(byAddr, at+16)
				result.Descriptors++
			}
			if len(byAddr) != 0 {
				return result, fmt.Errorf("unhandled TLS descriptor field relocation")
			}
			s.relocs = rels
			s.flags &^= 0xff
		}
	}
	if result.Descriptors == 0 && len(templateSections) != 0 {
		return result, fmt.Errorf("no TLS descriptors")
	}
	result.TextSectionsMerged, err = m.mergeExecutableText()
	if err != nil {
		return result, err
	}
	templateAddr := (m.end() + 7) &^ 7
	m.sections = append(m.sections, imageSection{name: "__bao_template", seg: "__TEXT", addr: templateAddr, size: uint64(len(template)), align: 3, data: template})
	m.symbols = append(m.symbols, macho.Symbol{Name: "_" + result.TemplateSymbol, Type: 0xf, Sect: uint8(len(m.sections)), Value: templateAddr})
	result.BoundarySymbols = m.synthesizeBoundaries()
	keep := make(map[string]bool)
	for _, name := range keepSymbols {
		keep["_"+name] = true
	}
	result.AliasesRemoved, err = m.coalesceTextAliases(keep)
	if err != nil {
		return result, err
	}
	if _, err = m.localizeAMD64GOTReferences(result.Namespace); err != nil {
		return result, err
	}
	result.LocalSymbolsRenamed = m.uniquifyLocals(result.Namespace)
	data, err := m.encode()
	if err != nil {
		return result, err
	}
	result.Objects = append(result.Objects, Object{Name: o.Name, Data: data})
	runtimes := [][]byte{tlsRuntime, tlsThunk}
	if result.Arch == "amd64" {
		runtimes = [][]byte{tlsRuntimeAMD64, tlsThunkAMD64}
	}
	for i, data := range runtimes {
		h, err := readImage(Object{Name: "runtime", Data: data})
		if err != nil {
			return result, err
		}
		for j := range h.symbols {
			s := &h.symbols[j]
			if strings.HasPrefix(s.Name, "_bao_") {
				s.Name = "_" + result.Namespace + strings.TrimPrefix(s.Name, "_bao_")
			}
		}
		data, err = h.encode()
		if err != nil {
			return result, err
		}
		result.Objects = append(result.Objects, Object{Name: fmt.Sprintf("bao-runtime-%d.o", i), Data: data})
	}
	result.TemplateSize = uint64(len(template))
	result.TemplateAlignment = align
	return result, nil
}
