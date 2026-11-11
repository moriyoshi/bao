// Package translate lowers Darwin arm64/amd64 native objects for Go 1.26.11's internal
// linker. It provides strict inspection/leaf packaging and a runtime translation
// pipeline for TLS, initializers, imports, DWARF and supported compact unwind frames.
// ELF is used as an input object container to retain native section alignment;
// the code ABI and final executable remain Darwin/Mach-O.
package translate

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
)

const LinkerProfile = "go1.26.11/darwin/arm64/internal"

type Object struct {
	Name string
	Data []byte
}

type Finding struct {
	Code    string `json:"code"`
	Section string `json:"section,omitempty"`
	Count   int    `json:"count,omitempty"`
	Detail  string `json:"detail"`
}

type Section struct {
	Name   string `json:"name"`
	Size   uint64 `json:"size"`
	Align  uint32 `json:"alignment_log2"`
	Flags  uint32 `json:"flags"`
	Relocs uint32 `json:"relocations"`
}

type ObjectReport struct {
	Name         string         `json:"name"`
	Architecture string         `json:"architecture,omitempty"`
	SHA256       string         `json:"sha256"`
	Sections     []Section      `json:"sections"`
	Relocations  map[string]int `json:"relocations"`
	Findings     []Finding      `json:"blockers,omitempty"`
}

type Report struct {
	Profile    string         `json:"linker_profile"`
	SHA256     string         `json:"input_sha256"`
	Objects    []ObjectReport `json:"objects"`
	Unresolved []string       `json:"unresolved_symbols,omitempty"`
	Findings   []Finding      `json:"blockers,omitempty"`
	Packable   bool           `json:"packable"`
}

var relocNames = []string{
	"ARM64_RELOC_UNSIGNED", "ARM64_RELOC_SUBTRACTOR", "ARM64_RELOC_BRANCH26",
	"ARM64_RELOC_PAGE21", "ARM64_RELOC_PAGEOFF12", "ARM64_RELOC_GOT_LOAD_PAGE21",
	"ARM64_RELOC_GOT_LOAD_PAGEOFF12", "ARM64_RELOC_POINTER_TO_GOT",
	"ARM64_RELOC_TLVP_LOAD_PAGE21", "ARM64_RELOC_TLVP_LOAD_PAGEOFF12", "ARM64_RELOC_ADDEND",
}

func relocName(t uint8) string {
	if int(t) < len(relocNames) {
		return relocNames[t]
	}
	return fmt.Sprintf("ARM64_RELOC_UNKNOWN_%d", t)
}

func Parse(name string, data []byte) ([]Object, error) {
	if bytes.HasPrefix(data, []byte("!<arch>\n")) {
		members, err := ar.Parse(data)
		if err != nil {
			return nil, err
		}
		out := make([]Object, 0, len(members))
		for _, m := range members {
			out = append(out, Object{Name: m.Name, Data: m.Data})
		}
		return out, nil
	}
	return []Object{{Name: name, Data: data}}, nil
}

func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// Inspect resolves archive-wide definitions but does not perform archive member
// selection or native weak/coalesced symbol resolution. Every member is included.
func Inspect(input []byte, objects []Object) (Report, error) {
	r := Report{Profile: LinkerProfile, SHA256: digest(input), Packable: true}
	if len(objects) == 0 {
		return r, fmt.Errorf("input has no object members")
	}
	defined := make(map[string]string)
	undefined := make(map[string]bool)
	for _, o := range objects {
		or, defs, undefs, err := inspectObject(o)
		if err != nil {
			return r, fmt.Errorf("%s: %w", o.Name, err)
		}
		r.Objects = append(r.Objects, or)
		if or.Architecture == "amd64" {
			r.Profile = "go1.26.11/darwin/amd64/internal"
		}
		for _, name := range defs {
			if prev, exists := defined[name]; exists {
				r.Findings = append(r.Findings, Finding{Code: "duplicate-definition", Detail: fmt.Sprintf("%s is defined in %s and %s; coalescing is unsupported", name, prev, o.Name)})
			}
			defined[name] = o.Name
		}
		for _, name := range undefs {
			undefined[name] = true
		}
		if len(or.Findings) != 0 {
			r.Packable = false
		}
	}
	for name := range undefined {
		if _, ok := defined[name]; !ok {
			r.Unresolved = append(r.Unresolved, name)
		}
	}
	sort.Strings(r.Unresolved)
	if len(r.Unresolved) != 0 {
		r.Findings = append(r.Findings, Finding{Code: "unresolved-symbols", Count: len(r.Unresolved), Detail: "requires import bindings or linker-synthesized symbols; automatic framework/data imports are unsupported"})
	}
	if len(r.Findings) != 0 {
		r.Packable = false
	}
	return r, nil
}

func openObject(o Object) (*macho.File, error) {
	f, err := macho.NewFile(bytes.NewReader(o.Data))
	if err != nil {
		return nil, fmt.Errorf("not a supported Mach-O object: %w", err)
	}
	validCPU := (f.Cpu == macho.CpuArm64 && f.SubCpu == 0) || (f.Cpu == macho.CpuAmd64 && f.SubCpu == 3)
	if f.Magic != macho.Magic64 || f.ByteOrder != binary.LittleEndian || !validCPU || f.Type != macho.TypeObj {
		return nil, fmt.Errorf("requires little-endian MH_OBJECT arm64 (not arm64e), got magic=%#x cpu=%s subtype=%d type=%s", f.Magic, f.Cpu, f.SubCpu, f.Type)
	}
	return f, nil
}

func HasExport(o Object, name string) (bool, error) {
	f, err := openObject(o)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if s.Name == name && s.Type&0xe0 == 0 && s.Type&0xf == 0xf && s.Sect != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

func imported(s *macho.Section) bool {
	return (s.Seg == "__TEXT" || s.Seg == "__DATA") && s.Name != "__eh_frame"
}

func inspectObject(o Object) (ObjectReport, []string, []string, error) {
	r := ObjectReport{Name: o.Name, SHA256: digest(o.Data), Relocations: make(map[string]int)}
	f, err := openObject(o)
	if err != nil {
		return r, nil, nil, err
	}
	defer f.Close()
	if f.Cpu == macho.CpuAmd64 {
		return inspectAMD64(o, f)
	}
	add := func(code, section, detail string, count int) {
		r.Findings = append(r.Findings, Finding{Code: code, Section: section, Detail: detail, Count: count})
	}
	segments := 0
	for _, l := range f.Loads {
		if _, ok := l.(*macho.Segment); ok {
			segments++
		}
		// These commands carry semantics that copying the bytes cannot preserve.
		switch uint32(f.ByteOrder.Uint32(l.Raw())) {
		case 0x2e: // LC_LINKER_OPTIMIZATION_HINT is optional, safe to ignore.
		case 0x29: // LC_DATA_IN_CODE is not consumed by Go's object reader.
			if len(l.Raw()) >= 16 && f.ByteOrder.Uint32(l.Raw()[12:]) != 0 {
				add("data-in-code", "", "nonempty LC_DATA_IN_CODE is unsupported", 1)
			}
		case 1, 2, 11, 25, 0x24, 0x32: // segments, symtab, dysymtab, versions.
		default:
			add("load-command", "", fmt.Sprintf("unhandled Mach-O load command %#x", f.ByteOrder.Uint32(l.Raw())), 1)
		}
	}
	if segments != 1 || f.Symtab == nil {
		add("object-layout", "", "Go requires one segment and a symbol table", 1)
	}
	for _, s := range f.Sections {
		name := s.Seg + "/" + s.Name
		r.Sections = append(r.Sections, Section{Name: name, Size: s.Size, Align: s.Align, Flags: s.Flags, Relocs: s.Nreloc})
		if s.Size != 0 {
			switch {
			case s.Name == "__eh_frame" || s.Name == "__compact_unwind":
				add("unwind-metadata", name, "Go skips this metadata; retaining Rust catch_unwind requires native unwind tables or explicit registration", 1)
			case s.Flags&0xff >= 0x11 && s.Flags&0xff <= 0x15:
				add("tls-lifecycle", name, "Go does not emit Darwin TLV sections/descriptors or arrange dyld TLS initialization; relocation lowering alone is insufficient", 1)
			case s.Flags&0xff == 9 || s.Flags&0xff == 10 || s.Flags&0xff == 0x16:
				add("initializers", name, "Go imports bytes without native constructor/terminator execution or ordering", int(s.Size/8))
			case strings.HasPrefix(s.Name, "__objc"):
				add("objc-metadata", name, "Objective-C image registration semantics are unsupported", 1)
			case s.Seg == "__DWARF" || s.Seg == "__LLVM": // Debug/bitcode is not needed for native execution.
			case !imported(s):
				add("ignored-section", name, "Go imports only __TEXT and __DATA (and skips __eh_frame)", 1)
			case s.Seg == "__TEXT" && s.Name != "__text" && s.Flags&0x80000400 != 0:
				add("text-classification", name, "Go classifies only __TEXT/__text as native text", 1)
			case s.Flags&0xff != 0 && s.Flags&0xff != 1 && s.Flags&0xff != 2 && s.Flags&0xff != 3 && s.Flags&0xff != 4 && s.Flags&0xff != 0xe:
				add("section-type", name, fmt.Sprintf("section type %#x has unsupported semantics", s.Flags&0xff), 1)
			}
			// loadmacho does not propagate section alignment. Keep the safe
			// subset to the natural 4-byte code / 8-byte data alignment.
			if imported(s) && ((s.Name == "__text" && s.Align > 2) || (s.Name != "__text" && (s.Align > 3 || s.Size < uint64(1)<<s.Align))) {
				add("section-alignment", name, "Go's Mach-O reader does not propagate section alignment; stronger alignment is unverified", 1)
			}
		}
		tlvp, unsupported, invalid, implicit := 0, 0, 0, 0
		for _, rel := range s.Relocs {
			r.Relocations[relocName(rel.Type)]++
			if rel.Scattered || uint64(rel.Addr)+(1<<rel.Len) > s.Size {
				invalid++
			}
			if rel.Type == 0 && imported(s) && !rel.Scattered && uint64(s.Offset)+uint64(rel.Addr)+(1<<rel.Len) <= uint64(len(o.Data)) {
				at := uint64(s.Offset) + uint64(rel.Addr)
				if rel.Len == 3 && binary.LittleEndian.Uint64(o.Data[at:]) != 0 || rel.Len == 2 && binary.LittleEndian.Uint32(o.Data[at:]) != 0 {
					implicit++
				}
			}
			if rel.Extern {
				if f.Symtab == nil || uint64(rel.Value) >= uint64(len(f.Symtab.Syms)) {
					invalid++
				}
			} else if rel.Type != 10 && (rel.Value == 0 || int(rel.Value) > len(f.Sections)) {
				invalid++
			}
			switch rel.Type {
			case 8, 9:
				tlvp++
			case 0, 2, 3, 4, 5, 6:
				// Conservative packager subset. More relocation forms are
				// understood by Go but require additional context validation.
				if !validBasicReloc(rel) {
					unsupported++
				}
			default:
				unsupported++
			}
		}
		if invalid > 0 {
			add("invalid-relocation", name, "relocation range or target is invalid", invalid)
		}
		if tlvp > 0 {
			add("tlvp-relocation", name, "Go rejects relocation types 2065/2066; probe-lower-tlvp can lower their address calculation only", tlvp)
		}
		if unsupported > 0 && imported(s) {
			add("relocation-form", name, "relocation forms outside the verified packager subset", unsupported)
		}
		if implicit > 0 {
			add("implicit-addend", name, "Go's Mach-O reader does not consume embedded integer addends; translate must normalize them", implicit)
		}
	}
	var defs, undefs []string
	if f.Symtab != nil {
		weak, special := 0, 0
		localDefinitions := make(map[string]macho.Symbol)
		localCollisions := 0
		// Go's findfunc table has uint8 subbucket indices. Count all native
		// symbols in sliding 4 KiB windows; relative placement is unknown.
		var textAddrs []uint64
		for _, sym := range f.Symtab.Syms {
			if sym.Type&0xe0 != 0 {
				continue
			}
			if sym.Type&1 == 0 && sym.Sect != 0 {
				name := strings.TrimPrefix(sym.Name, "_")
				if old, ok := localDefinitions[name]; ok && (old.Value != sym.Value || old.Sect != sym.Sect) {
					localCollisions++
				}
				localDefinitions[name] = sym
			}
			if len(sym.Name) < 2 || sym.Type&0xe != 0 && sym.Type&0xe != 0xe {
				special++
			}
			if sym.Desc&0xc0 != 0 {
				weak++
			}
			if int(sym.Sect) > len(f.Sections) {
				return r, nil, nil, fmt.Errorf("invalid section index for %q", sym.Name)
			}
			if sym.Type&1 != 0 {
				if sym.Sect != 0 {
					defs = append(defs, sym.Name)
				} else {
					undefs = append(undefs, sym.Name)
				}
			}
			if sym.Sect != 0 {
				s := f.Sections[sym.Sect-1]
				if sym.Value < s.Addr || sym.Value > s.Addr+s.Size {
					special++
				}
				if s.Seg == "__TEXT" && s.Name == "__text" {
					textAddrs = append(textAddrs, sym.Value)
				}
			}
		}
		sort.Slice(textAddrs, func(i, j int) bool { return textAddrs[i] < textAddrs[j] })
		maxDensity := 0
		for lo, hi := 0, 0; hi < len(textAddrs); hi++ {
			for textAddrs[hi]-textAddrs[lo] >= 4096 {
				lo++
			}
			maxDensity = max(maxDensity, hi-lo+1)
		}
		if maxDensity >= 256 {
			add("function-density", "__TEXT/__text", "at least 256 native symbols in a 4 KiB window; Go findfunc subbucket indices can overflow depending on placement", maxDensity)
		}
		if weak > 0 {
			add("weak-symbols", "", "native weak/coalesced resolution is not implemented by this packager", weak)
		}
		if special > 0 {
			add("symbol-form", "", "unsupported symbol names, kinds, or section-relative values", special)
		}
		if localCollisions > 0 {
			add("local-symbol-collision", "", "Mach-O local names are not unique; Go's Mach-O reader interns them by name instead of index", localCollisions)
		}
	}
	return r, defs, undefs, nil
}

func validBasicReloc(r macho.Reloc) bool {
	if r.Scattered {
		return false
	}
	switch r.Type {
	case 0:
		return !r.Pcrel && r.Len == 3
	case 2, 3, 5:
		return r.Pcrel && r.Len == 2 && r.Extern
	case 4, 6:
		return !r.Pcrel && r.Len == 2 && r.Extern
	}
	return false
}

// LowerTLVP replaces the TLVP address relocations with GOT_LOAD relocations.
// The descriptor remains the target. Go relaxes a locally defined descriptor's
// ADRP/LDR into ADRP/ADD, as a native linker may do for non-preemptible TLV
// descriptors. No TLS storage, descriptor fields, or native calls are removed.
// The result is an INCOMPLETE intermediate, never a certified runtime artifact.
func LowerTLVP(o Object) ([]byte, int, error) {
	f, err := openObject(o)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	out := bytes.Clone(o.Data)
	if f.Cpu == macho.CpuAmd64 {
		return lowerTLVPAMD64(f, out)
	}
	count := 0
	for _, s := range f.Sections {
		for i, r := range s.Relocs {
			if r.Type != 8 && r.Type != 9 {
				continue
			}
			if r.Scattered || !r.Extern || r.Len != 2 || r.Pcrel != (r.Type == 8) || uint64(r.Addr)+4 > s.Size || uint64(s.Offset)+uint64(r.Addr)+4 > uint64(len(out)) {
				return nil, 0, fmt.Errorf("%s: unsupported TLVP form at %#x", s.Name, r.Addr)
			}
			if f.Symtab == nil || int(r.Value) >= len(f.Symtab.Syms) {
				return nil, 0, fmt.Errorf("TLVP target index out of range")
			}
			sym := f.Symtab.Syms[r.Value]
			if sym.Sect == 0 || int(sym.Sect) > len(f.Sections) || f.Sections[sym.Sect-1].Flags&0xff != 0x13 {
				return nil, 0, fmt.Errorf("%s: TLVP target %s is not a locally defined TLS descriptor", s.Name, sym.Name)
			}
			insn := binary.LittleEndian.Uint32(out[uint64(s.Offset)+uint64(r.Addr):])
			if (r.Type == 8 && insn&0x9f000000 != 0x90000000) || (r.Type == 9 && insn&0xffc00000 != 0xf9400000) {
				return nil, 0, fmt.Errorf("%s: unsupported TLVP instruction %#08x at %#x", s.Name, insn, r.Addr)
			}
			pos := uint64(s.Reloff) + uint64(i)*8 + 4
			if pos+4 > uint64(len(out)) {
				return nil, 0, fmt.Errorf("TLVP relocation outside file")
			}
			v := binary.LittleEndian.Uint32(out[pos:])
			binary.LittleEndian.PutUint32(out[pos:], (v&0x0fffffff)|uint32(r.Type-3)<<28)
			count++
		}
	}
	return out, count, nil
}
