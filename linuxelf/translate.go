package linuxelf

import (
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed native/runtime.bin
var runtimeObject []byte

//go:embed native/loong64/runtime.bin
var runtimeLoong64 []byte

//go:embed native/ppc64le/runtime.bin
var runtimePPC64LE []byte

//go:embed native/amd64/runtime.bin
var runtimeAMD64 []byte

type Import struct {
	Local   string `json:"go_symbol"`
	Remote  string `json:"dynamic_symbol"`
	Library string `json:"library"`
}

// ValidateSysroot checks the target shared-library export metadata required by
// the Linux translator. It neither loads libraries nor executes target code.
func ValidateSysroot(root string) error {
	_, err := systemSymbols(root)
	return err
}

type Fixup struct {
	Location string `json:"location_symbol"`
	Import   string `json:"import_symbol"`
	Addend   int64  `json:"addend"`
}
type Table struct {
	Symbol   string `json:"symbol"`
	Count    int    `json:"count"`
	Priority int    `json:"priority"`
}

// CappedAlignment records an executable section linked below its requested
// alignment because of -linux-max-text-alignment.
type CappedAlignment struct {
	Section   string `json:"section"`
	Requested uint64 `json:"requested"`
	Applied   uint64 `json:"applied"`
}

// MaxSafeTextAlignment is the largest executable section alignment that stock
// Go's linker places correctly. It starts runtime.text at -T, which is only
// 4 KiB-aligned by default (for example 0x11000 on linux/arm64), assigns text
// symbol addresses from there, and then rounds the .text section start up to
// the largest symbol alignment. Method offsets (R_METHODOFF) are relative to
// that rounded start, but the runtime adds them to runtime.text, so every
// itab built at run time calls the wrong function.
const MaxSafeTextAlignment = 4096

type Plan struct {
	Arch                 string            `json:"goarch"`
	LocalFixups          []LocalFixup      `json:"local_pointer_fixups,omitempty"`
	Status               string            `json:"status"`
	Namespace            string            `json:"namespace"`
	InputSHA256          string            `json:"input_sha256"`
	TLSDescriptors       int               `json:"tls_descriptors"`
	TLSTemplateSize      uint64            `json:"tls_template_size"`
	TLSTemplateAlignment uint64            `json:"tls_template_alignment"`
	TLSTemplateSymbol    string            `json:"tls_template_symbol"`
	Unwind               []string          `json:"unwind_sections"`
	Constructors         []Table           `json:"constructor_tables"`
	Finalizers           []Table           `json:"finalizer_tables,omitempty"`
	RegisterFrame        string            `json:"local_register_frame,omitempty"`
	Imports              []Import          `json:"imports"`
	Fixups               []Fixup           `json:"pointer_fixups"`
	WeakZero             []string          `json:"unavailable_weak_symbols"`
	CappedTextAlignments []CappedAlignment `json:"linux_capped_text_alignments,omitempty"`
	Artifacts            map[string]string `json:"artifact_sha256"`
	Objects              [][]byte          `json:"-"`
}

func (p *Plan) Runtime(name string) string { return p.Namespace + name }

// An undefined weak reference does not request a shared library in an ELF
// native link. Bind it only when a strong import already needs that provider.
func (p *Plan) requiredLibraries(images []*image, index map[string]string) map[string]bool {
	defined := map[string]bool{}
	for _, m := range images {
		for _, s := range m.symbols {
			if s.sect != 0 && elf.ST_BIND(s.info) != elf.STB_LOCAL {
				defined[s.name] = true
			}
		}
	}
	needed := map[string]bool{}
	for _, m := range images {
		for _, s := range m.symbols {
			if s.sect == 0 && elf.ST_BIND(s.info) != elf.STB_LOCAL && elf.ST_BIND(s.info) != elf.STB_WEAK && !defined[s.name] && index[s.name] != "" {
				needed[index[s.name]] = true
			}
		}
	}
	if p.RegisterFrame == "" && len(p.Unwind) != 0 {
		needed["libgcc_s.so.1"] = true
	}
	return needed
}

// systemSymbols derives import install names from actual target ELF dynamic
// symbol tables. A Linux sysroot is required even on a cross-compiling host.
func systemSymbols(root string) (map[string]string, error) {
	return systemSymbolsMachine(root, elf.EM_AARCH64)
}

func ValidateSysrootTarget(root, arch string) error {
	machine := elf.EM_AARCH64
	switch arch {
	case "amd64":
		machine = elf.EM_X86_64
	case "loong64":
		machine = elf.EM_LOONGARCH
	case "ppc64le":
		machine = elf.EM_PPC64
	case "arm64":
	default:
		return fmt.Errorf("unsupported Linux architecture %s", arch)
	}
	_, err := systemSymbolsMachine(root, machine)
	return err
}

// validSystemLibrary accepts a shared-object file name, never a path.
func validSystemLibrary(name string) bool {
	if len(name) > 128 || !strings.Contains(name, ".so") || strings.HasPrefix(name, "-") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '+') {
			return false
		}
	}
	return true
}

func systemSymbolsMachine(root string, machine elf.Machine, extra ...string) (map[string]string, error) {
	if root == "" {
		return nil, fmt.Errorf("-sysroot containing Linux arm64 glibc libraries is required")
	}
	required := map[string]bool{"libc.so.6": true, "libgcc_s.so.1": true}
	seen := map[string]bool{}
	for _, name := range extra {
		if !validSystemLibrary(name) {
			return nil, fmt.Errorf("invalid Linux system library %q: use a shared-object file name such as libfoo.so.1", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate Linux system library %s", name)
		}
		seen[name] = true
		required[name] = true
	}
	index := map[string]string{}
	// The glibc/C++ runtime set stays first: an extra library cannot replace one
	// of its symbols, because the first exporter of a name wins below.
	for _, name := range append([]string{"libc.so.6", "libm.so.6", "libgcc_s.so.1", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libstdc++.so.6", "ld64.so.2", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1", "ld-linux-loongarch-lp64d.so.1"}, extra...) {
		var path string
		for _, dir := range []string{"lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu", "lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu", "lib/loongarch64-linux-gnu", "usr/lib/loongarch64-linux-gnu", "lib/powerpc64le-linux-gnu", "usr/lib/powerpc64le-linux-gnu", "lib64", "lib", "usr/lib64", "usr/lib"} {
			candidate := filepath.Join(root, dir, name)
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
		if path == "" {
			if required[name] {
				return nil, fmt.Errorf("missing target library %s", name)
			}
			continue
		}
		f, err := elf.Open(path)
		if err != nil {
			return nil, err
		}
		if f.Machine != machine || f.Type != elf.ET_DYN || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
			f.Close()
			return nil, fmt.Errorf("%s is not Linux AArch64 ELF64 shared library", path)
		}
		syms, err := f.DynamicSymbols()
		f.Close()
		if err != nil {
			return nil, err
		}
		for _, s := range syms {
			if s.Section != elf.SHN_UNDEF && elf.ST_BIND(s.Info) != elf.STB_LOCAL && (elf.ST_TYPE(s.Info) == elf.STT_FUNC || elf.ST_TYPE(s.Info) == elf.STT_OBJECT || elf.ST_TYPE(s.Info) == elf.STT_GNU_IFUNC || elf.ST_TYPE(s.Info) == elf.STT_NOTYPE) {
				if _, ok := index[s.Name]; !ok {
					index[s.Name] = name
				}
			}
		}
	}
	if index["__register_frame"] == "" {
		return nil, fmt.Errorf("target libgcc_s must export __register_frame")
	}
	return index, nil
}

// sysrootObjects lists shared objects in a sysroot's library directories for one
// machine, in search order. A base name found earlier hides later copies.
func sysrootObjects(root string, machine elf.Machine) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, dir := range []string{"lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu", "lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu", "lib/loongarch64-linux-gnu", "usr/lib/loongarch64-linux-gnu", "lib/powerpc64le-linux-gnu", "usr/lib/powerpc64le-linux-gnu", "lib64", "lib", "usr/lib64", "usr/lib"} {
		matches, err := filepath.Glob(filepath.Join(root, dir, "*.so.*"))
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		for _, path := range matches {
			base := filepath.Base(path)
			if seen[base] {
				continue
			}
			f, err := elf.Open(path)
			if err != nil {
				continue
			}
			ok := f.Machine == machine && f.Type == elf.ET_DYN
			f.Close()
			if ok {
				seen[base] = true
				out = append(out, path)
			}
		}
	}
	return out, nil
}

func linuxMachine(arch string) (elf.Machine, error) {
	machine := map[string]elf.Machine{"arm64": elf.EM_AARCH64, "amd64": elf.EM_X86_64, "loong64": elf.EM_LOONGARCH, "ppc64le": elf.EM_PPC64}[arch]
	if machine == elf.EM_NONE {
		return machine, fmt.Errorf("unsupported Linux architecture %s", arch)
	}
	return machine, nil
}

// SearchableLibraries names every shared object Exporters would examine.
func SearchableLibraries(root, arch string) ([]string, error) {
	machine, err := linuxMachine(arch)
	if err != nil {
		return nil, err
	}
	paths, err := sysrootObjects(root, machine)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(paths))
	for i, path := range paths {
		names[i] = filepath.Base(path)
	}
	sort.Strings(names)
	return names, nil
}

// Exporters finds which sysroot shared objects export each name. It is advisory
// and never adds a library to a translation; that takes -linux-system-library.
func Exporters(root, arch string, names []string) (map[string][]string, error) {
	machine, err := linuxMachine(arch)
	if err != nil {
		return nil, err
	}
	paths, err := sysrootObjects(root, machine)
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	out := map[string][]string{}
	for _, path := range paths {
		f, err := elf.Open(path)
		if err != nil {
			continue
		}
		syms, err := f.DynamicSymbols()
		f.Close()
		if err != nil {
			continue
		}
		for _, s := range syms {
			if s.Section != elf.SHN_UNDEF && elf.ST_BIND(s.Info) != elf.STB_LOCAL && wanted[s.Name] {
				out[s.Name] = append(out[s.Name], filepath.Base(path))
			}
		}
	}
	return out, nil
}

// UnresolvedError lists every import absent from the searched sysroot libraries.
type UnresolvedError struct{ Names []string }

func (e *UnresolvedError) Error() string {
	if len(e.Names) == 1 {
		return "target sysroot does not export " + e.Names[0]
	}
	return fmt.Sprintf("target sysroot does not export %d symbols: %s", len(e.Names), strings.Join(e.Names, ", "))
}

// Options configures TranslateWithOptions.
type Options struct {
	// MaxTextAlignment, when MaxSafeTextAlignment, links executable sections
	// requesting more at that alignment and records them in the plan.
	// Otherwise such sections are rejected.
	MaxTextAlignment uint64
	// SystemLibraries names additional sysroot shared objects, such as
	// libxcb.so.1, whose exports may satisfy native imports. Each must exist.
	SystemLibraries []string
}

func Translate(input []byte, sysroot string, exports []string) (*Plan, error) {
	return TranslateWithOptions(input, sysroot, exports, Options{})
}

func TranslateWithOptions(input []byte, sysroot string, exports []string, opts Options) (*Plan, error) {
	if opts.MaxTextAlignment != 0 && opts.MaxTextAlignment != MaxSafeTextAlignment {
		return nil, fmt.Errorf("unsupported Linux maximum text alignment %d; only %d is supported", opts.MaxTextAlignment, MaxSafeTextAlignment)
	}
	main, err := parse(input)
	if err != nil {
		return nil, err
	}
	runtimeData := runtimeObject
	switch main.effectiveMachine() {
	case elf.EM_X86_64:
		runtimeData = runtimeAMD64
	case elf.EM_LOONGARCH:
		runtimeData = runtimeLoong64
	case elf.EM_PPC64:
		runtimeData = runtimePPC64LE
	}
	helper, err := parse(runtimeData)
	if err != nil {
		return nil, err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(input))
	p := &Plan{Arch: main.arch(), Status: "TRANSLATED: target link and execution require separate verification", Namespace: "bao_elf_" + digest[:12] + "_", InputSHA256: digest, Artifacts: map[string]string{}}
	images := []*image{main, helper}
	defined := map[string]bool{}
	for _, m := range images {
		for _, s := range m.symbols {
			if s.sect != 0 && elf.ST_BIND(s.info) != elf.STB_LOCAL {
				defined[s.name] = true
			}
		}
	}
	for _, s := range exports {
		if !defined[s] {
			return nil, fmt.Errorf("missing external definition %q", s)
		}
	}
	if defined["__register_frame"] {
		for _, s := range main.symbols {
			if s.name == "__register_frame" && s.sect != 0 && elf.ST_TYPE(s.info) == elf.STT_FUNC {
				p.RegisterFrame = "__register_frame"
			}
		}
		if p.RegisterFrame == "" {
			return nil, fmt.Errorf("local __register_frame must be a native function")
		}
	}
	// Namespace every original helper export/reference, then redirect only this
	// image's compiler TLS teardown and DSO references to that private runtime.
	for _, m := range images {
		for i := range m.symbols {
			s := &m.symbols[i]
			if strings.HasPrefix(s.name, "bao_") {
				if m == helper {
					s.name = p.Namespace + strings.TrimPrefix(s.name, "bao_")
				}
			}
		}
	}
	for i := range main.symbols {
		s := &main.symbols[i]
		if s.sect == 0 {
			switch s.name {
			case "__cxa_thread_atexit_impl", "__cxa_thread_atexit":
				s.name = p.Runtime("tls_atexit")
			case "__tls_get_addr":
				if main.effectiveMachine() != elf.EM_AARCH64 {
					s.name = p.tlsResolver(main)
				}
			case "__dso_handle":
				s.name = p.Runtime("dso_handle")
			}
		}
	}
	if err := p.lowerTLSForMachine(main); err != nil {
		return nil, err
	}
	for oi, m := range images {
		if err := p.normalizeCross(m, oi); err != nil {
			return nil, err
		}
		for si := range m.sections {
			s := &m.sections[si]
			if s.flags&elf.SHF_ALLOC == 0 {
				continue
			}
			if s.flags&elf.SHF_TLS != 0 {
				return nil, fmt.Errorf("unlowered ELF TLS section %s", s.name)
			}
			if err := p.limitTextAlignment(s, opts.MaxTextAlignment); err != nil {
				return nil, err
			}
			if s.flags&elf.SHF_COMPRESSED != 0 || s.flags&elf.SHF_LINK_ORDER != 0 {
				return nil, fmt.Errorf("unsupported allocated ELF section flags in %s", s.name)
			}
			if s.typ == elf.SHT_INIT_ARRAY || s.typ == elf.SHT_FINI_ARRAY {
				if s.size%8 != 0 {
					return nil, fmt.Errorf("unsupported initializer table layout")
				}
				priority := 65535
				prefix := ".init_array."
				finalizer := s.typ == elf.SHT_FINI_ARRAY
				if finalizer {
					prefix = ".fini_array."
				}
				if strings.HasPrefix(s.name, prefix) {
					priority, err = strconv.Atoi(strings.TrimPrefix(s.name, prefix))
					if err != nil {
						return nil, fmt.Errorf("invalid init priority: %w", err)
					}
					if priority < 0 || priority > 65535 {
						return nil, fmt.Errorf("initializer/finalizer priority outside ELF range: %d", priority)
					}
				}
				name := fmt.Sprintf("%sctors_%d_%d", p.Namespace, oi, si)
				if finalizer {
					name = fmt.Sprintf("%sfinis_%d_%d", p.Namespace, oi, si)
				}
				m.addSymbol(name, uint16(si), 0, s.size)
				table := Table{Symbol: name, Count: int(s.size / 8), Priority: priority}
				if finalizer {
					p.Finalizers = append(p.Finalizers, table)
				} else {
					p.Constructors = append(p.Constructors, table)
				}
				s = &m.sections[si]
				s.typ = elf.SHT_PROGBITS
			}
			if m.effectiveMachine() == elf.EM_X86_64 && s.typ == elf.SectionType(0x70000001) {
				if err := normalizeAMD64Unwind(s); err != nil {
					return nil, err
				}
			}
			if s.typ != elf.SHT_PROGBITS && s.typ != elf.SHT_NOBITS {
				return nil, fmt.Errorf("unsupported allocated section %s: %s", s.name, s.typ)
			}
			if s.name == ".eh_frame" && s.size != 0 {
				if err := validateFrames(s.data); err != nil {
					return nil, err
				}
				s.data = append(s.data, 0, 0, 0, 0)
				s.size = uint64(len(s.data))
				name := fmt.Sprintf("%sunwind_%d", p.Namespace, oi)
				m.addSymbol(name, uint16(si), 0, s.size)
				p.Unwind = append(p.Unwind, name)
			}
			s = &m.sections[si]
			s.flags &^= elf.SHF_GROUP | elf.SectionFlag(0x200000)
			s.name = fmt.Sprintf(".bao.%s.%d.%d.%s", digest[:12], oi, si, strings.TrimPrefix(s.name, "."))
		}
		if err := normalizeSymbols(m); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(p.Constructors, func(i, j int) bool { return p.Constructors[i].Priority < p.Constructors[j].Priority })
	for i, j := 0, len(p.Finalizers)-1; i < j; i, j = i+1, j-1 {
		p.Finalizers[i], p.Finalizers[j] = p.Finalizers[j], p.Finalizers[i]
	}
	sort.SliceStable(p.Finalizers, func(i, j int) bool { return p.Finalizers[i].Priority > p.Finalizers[j].Priority })
	index, err := systemSymbolsMachine(sysroot, main.effectiveMachine(), opts.SystemLibraries...)
	if err != nil {
		return nil, err
	}
	if err := p.bind(images, index); err != nil {
		return nil, err
	}
	for i, m := range images {
		b, err := m.encode()
		if err != nil {
			return nil, err
		}
		p.Objects = append(p.Objects, b)
		name := fmt.Sprintf("native_%d_linux_%s.syso", i, p.Arch)
		p.Artifacts[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	return p, nil
}

// Retire symbols that cannot or need not reach Go's linker, and reject the
// rest of the forms outside the supported profile.
func normalizeSymbols(m *image) error {
	referenced := map[uint32]bool{}
	for _, s := range m.sections {
		if s.flags&elf.SHF_ALLOC != 0 {
			for _, r := range s.relocs {
				referenced[r.sym] = true
			}
		}
	}
	for i := 1; i < len(m.symbols); i++ {
		s := &m.symbols[i]
		typ := elf.ST_TYPE(s.info)
		if s.sect >= uint16(elf.SHN_LORESERVE) {
			// Assembler constants such as OpenSSL perlasm's `mixin` are
			// local absolute symbols that no code or data refers to.
			unused := elf.ST_BIND(s.info) == elf.STB_LOCAL && s.sect == uint16(elf.SHN_ABS) && !referenced[uint32(i)]
			if typ == elf.STT_FILE || unused {
				s.info = byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE)
				s.name = "$d.bao.ignored"
				s.sect = 0
				s.value = 0
				continue
			}
			if s.sect == uint16(elf.SHN_ABS) && referenced[uint32(i)] {
				return fmt.Errorf("unsupported relocation against absolute symbol %s", s.name)
			}
			return fmt.Errorf("unsupported absolute/common/extended symbol %s", s.name)
		}
		if int(s.sect) >= len(m.sections) {
			return fmt.Errorf("invalid native symbol section")
		}
		if s.sect != 0 && m.sections[s.sect].flags&elf.SHF_ALLOC == 0 {
			s.info = byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE)
			s.name = "$d.bao.ignored"
			s.sect = 0
			s.value = 0
			continue
		}
		if typ != elf.STT_FUNC && typ != elf.STT_OBJECT && typ != elf.STT_NOTYPE && typ != elf.STT_SECTION {
			return fmt.Errorf("unsupported native symbol type %s: %s", s.name, typ)
		}
		if err := normalizeUnique(s); err != nil {
			return err
		}
		if s.sect != 0 && (s.value > m.sections[s.sect].size || s.size > m.sections[s.sect].size-s.value) {
			return fmt.Errorf("native symbol outside section: %s", s.name)
		}
	}
	return nil
}

func (p *Plan) limitTextAlignment(s *section, max uint64) error {
	if s.flags&elf.SHF_EXECINSTR == 0 || s.align <= MaxSafeTextAlignment {
		return nil
	}
	if max != MaxSafeTextAlignment {
		return fmt.Errorf("executable section %s requests %d-byte alignment; stock Go's linker misplaces runtime.text when text is aligned beyond %d bytes, corrupting interface method calls. -linux-max-text-alignment %d links it at %d bytes", s.name, s.align, MaxSafeTextAlignment, MaxSafeTextAlignment, MaxSafeTextAlignment)
	}
	p.CappedTextAlignments = append(p.CappedTextAlignments, CappedAlignment{s.name, s.align, MaxSafeTextAlignment})
	s.align = MaxSafeTextAlignment
	return nil
}

// Partial native linking has already coalesced GNU unique C++ objects. The
// supported single-image profile has no DSO interposition/unloading; preserve
// one global identity in stock Go's supported symbol bindings.
func normalizeUnique(s *symbol) error {
	if elf.ST_BIND(s.info) != elf.SymBind(10) { // STB_GNU_UNIQUE
		return nil
	}
	if elf.ST_TYPE(s.info) != elf.STT_OBJECT || s.sect == 0 {
		return fmt.Errorf("unsupported GNU unique symbol %s", s.name)
	}
	s.info = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT)
	return nil
}

func validateFrames(b []byte) error {
	for off := 0; off < len(b); {
		if len(b)-off < 4 {
			return fmt.Errorf("truncated native unwind record")
		}
		n := int(binary.LittleEndian.Uint32(b[off:]))
		if n == 0 {
			for _, v := range b[off:] {
				if v != 0 {
					return fmt.Errorf("unwind payload after terminator")
				}
			}
			return nil
		}
		if n < 4 || n == int(^uint32(0)) || n > len(b)-off-4 {
			return fmt.Errorf("unsupported native unwind record length")
		}
		off += n + 4
	}
	return nil
}

func (p *Plan) lowerTLS(m *image) error {
	offsets := map[uint16]uint64{}
	alignment := uint64(8)
	var template []byte
	for i, s := range m.sections {
		if s.flags&elf.SHF_TLS == 0 {
			continue
		}
		if s.typ != elf.SHT_PROGBITS && s.typ != elf.SHT_NOBITS {
			return fmt.Errorf("unsupported native TLS section %s", s.name)
		}
		alignment = max(alignment, s.align)
		for uint64(len(template))%s.align != 0 {
			template = append(template, 0)
		}
		offsets[uint16(i)] = uint64(len(template))
		if s.typ == elf.SHT_NOBITS {
			template = append(template, make([]byte, s.size)...)
		} else {
			template = append(template, s.data...)
		}
		m.sections[i].flags &^= elf.SHF_ALLOC | elf.SHF_TLS
	}
	if len(template) == 0 {
		template = make([]byte, 8)
	}
	for uint64(len(template))%alignment != 0 {
		template = append(template, 0)
	}
	p.TLSTemplateSize = uint64(len(template))
	p.TLSTemplateAlignment = alignment
	p.TLSTemplateSymbol = p.Runtime("tls_template")
	templateSection := m.addSection(section{name: ".bao.tls_template", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: alignment, size: uint64(len(template)), data: template})
	m.addSymbol(p.TLSTemplateSymbol, templateSection, 0, uint64(len(template)))
	if err := moveTemplateRelocs(m, offsets, templateSection); err != nil {
		return err
	}
	descSection := m.addSection(section{name: ".bao.tls_descriptors", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8})
	thunk := m.addSymbol(p.Runtime("tls_thunk"), 0, 0, 0)
	type target struct {
		sym uint32
		add int64
	}
	descriptors := map[target]uint32{}
	for si := range m.sections {
		if m.sections[si].flags&elf.SHF_ALLOC == 0 {
			continue
		}
		s := &m.sections[si]
		var out []reloc
		for ri := 0; ri < len(s.relocs); ri++ {
			r := s.relocs[ri]
			if r.typ == elf.R_AARCH64_TLSDESC_ADR_PAGE21 {
				if ri+3 >= len(s.relocs) {
					return fmt.Errorf("incomplete TLSDESC sequence")
				}
				group := s.relocs[ri : ri+4]
				types := []elf.R_AARCH64{elf.R_AARCH64_TLSDESC_ADR_PAGE21, elf.R_AARCH64(563), elf.R_AARCH64(564), elf.R_AARCH64_TLSDESC_CALL}
				// GCC can load the resolver into x2/x3/etc.; x0 still holds
				// the descriptor argument. Require the matching BLR register,
				// preserve every instruction, and keep the descriptor base x0.
				if group[1].off+4 > uint64(len(s.data)) {
					return fmt.Errorf("TLSDESC resolver load outside native text")
				}
				resolver := binary.LittleEndian.Uint32(s.data[group[1].off:]) & 31
				if resolver == 0 || resolver == 31 {
					return fmt.Errorf("invalid TLSDESC resolver register")
				}
				words := []uint32{0x90000000, 0xf9400000 | resolver, 0x91000000, 0xd63f0000 | resolver<<5}
				masks := []uint32{0x9f00001f, 0xffc003ff, 0xffc003ff, 0xffffffff}
				for j, q := range group {
					if q.typ != types[j] || q.sym != r.sym || q.add != r.add || q.off != r.off+uint64(j*4) || q.off+4 > uint64(len(s.data)) || binary.LittleEndian.Uint32(s.data[q.off:])&masks[j] != words[j] {
						return fmt.Errorf("unsupported AArch64 TLSDESC instruction/relocation sequence")
					}
				}
				sym := m.symbols[r.sym]
				base, ok := offsets[sym.sect]
				if !ok || elf.ST_TYPE(sym.info) != elf.STT_TLS || int64(base+sym.value)+r.add < 0 || uint64(int64(base+sym.value)+r.add) >= uint64(len(template)) {
					return fmt.Errorf("TLSDESC target is not local image TLS")
				}
				key := target{r.sym, r.add}
				idx, ok := descriptors[key]
				if !ok {
					d := &m.sections[descSection]
					off := uint64(len(d.data))
					d.data = append(d.data, make([]byte, 16)...)
					binary.LittleEndian.PutUint64(d.data[off+8:], uint64(int64(base+sym.value)+r.add))
					d.relocs = append(d.relocs, reloc{off: off, sym: thunk, typ: elf.R_AARCH64_ABS64})
					d.size = uint64(len(d.data))
					idx = m.addSymbol(fmt.Sprintf("%stls_desc_%d", p.Namespace, len(descriptors)), descSection, off, 16)
					descriptors[key] = idx
					s = &m.sections[si]
				}
				for j, typ := range []elf.R_AARCH64{elf.R_AARCH64_ADR_PREL_PG_HI21, elf.R_AARCH64_LDST64_ABS_LO12_NC, elf.R_AARCH64_ADD_ABS_LO12_NC} {
					q := group[j]
					q.typ = typ
					q.sym = idx
					q.add = 0
					out = append(out, q)
				}
				ri += 3
				continue
			}
			if r.typ >= elf.R_AARCH64_TLSGD_ADR_PREL21 {
				return fmt.Errorf("unsupported native TLS relocation %s", r.typ)
			}
			if elf.ST_TYPE(m.symbols[r.sym].info) == elf.STT_TLS {
				return fmt.Errorf("non-TLSDESC reference to native TLS")
			}
			out = append(out, r)
		}
		m.sections[si].relocs = out
	}
	p.TLSDescriptors = len(descriptors)
	return nil
}

// TLS initializers may hold absolute pointers to ordinary image data, such as
// mimalloc's `__thread mi_heap_t *_mi_heap_default = &_mi_heap_empty`. Move
// them onto the native template: the Go linker, or the import fixup pass that
// runs before native code, writes each pointer before any thread copies it.
// A pointer to TLS would need a per-thread value, so it is rejected.
func moveTemplateRelocs(m *image, offsets map[uint16]uint64, template uint16) error {
	abs := map[elf.Machine]uint32{elf.EM_AARCH64: uint32(elf.R_AARCH64_ABS64), elf.EM_X86_64: uint32(elf.R_X86_64_64), elf.EM_LOONGARCH: uint32(elf.R_LARCH_64), elf.EM_PPC64: uint32(elf.R_PPC64_ADDR64)}[m.effectiveMachine()]
	for si := range m.sections {
		base, ok := offsets[uint16(si)]
		if !ok {
			continue
		}
		s := &m.sections[si]
		for _, r := range s.relocs {
			sym := m.symbols[r.sym]
			if uint32(r.typ) != abs {
				return fmt.Errorf("unsupported relocation %d in native TLS template %s; only absolute pointers are supported", r.typ, s.name)
			}
			if r.off+8 > uint64(len(s.data)) {
				return fmt.Errorf("absolute pointer outside native TLS template %s", s.name)
			}
			if _, tls := offsets[sym.sect]; tls || elf.ST_TYPE(sym.info) == elf.STT_TLS {
				return fmt.Errorf("native TLS template %s points into TLS through %s", s.name, sym.name)
			}
			r.off += base
			m.sections[template].relocs = append(m.sections[template].relocs, r)
		}
		s.relocs = nil
	}
	return nil
}

// Go's linker does not apply AArch64 conditional (B.cond, CBZ/CBNZ) or
// test-bit (TBZ/TBNZ) branch relocations. Hand-written assembly such as
// OpenSSL's uses them against symbols in the same section, where the
// displacement is already final; resolve those in place.
func resolveShortBranch(m *image, si uint16, r reloc) error {
	s := &m.sections[si]
	sym := m.symbols[r.sym]
	bits, opcode, opmask := 19, uint32(0x54000000), uint32(0xff000010) // B.cond
	if r.typ == elf.R_AARCH64_TSTBR14 {
		bits, opcode, opmask = 14, 0x36000000, 0x7e000000 // TBZ/TBNZ
	}
	if sym.sect != si || s.flags&elf.SHF_EXECINSTR == 0 || r.off+4 > uint64(len(s.data)) {
		return fmt.Errorf("%s from %s to %s outside its section is unsupported", r.typ, s.name, sym.name)
	}
	word := binary.LittleEndian.Uint32(s.data[r.off:])
	if word&opmask != opcode && !(r.typ == elf.R_AARCH64_CONDBR19 && word&0x7e000000 == 0x34000000) { // CBZ/CBNZ
		return fmt.Errorf("%s at %s+%#x is not a branch instruction", r.typ, s.name, r.off)
	}
	delta := int64(sym.value) + r.add - int64(r.off)
	if limit := int64(1) << (bits + 1); delta&3 != 0 || delta < -limit || delta >= limit {
		return fmt.Errorf("%s from %s+%#x to %s is misaligned or out of range", r.typ, s.name, r.off, sym.name)
	}
	mask := uint32(1)<<bits - 1
	binary.LittleEndian.PutUint32(s.data[r.off:], word&^(mask<<5)|uint32(delta>>2)&mask<<5)
	return nil
}

func supportedReloc(t elf.R_AARCH64) bool {
	switch t {
	case elf.R_AARCH64_NONE, elf.R_AARCH64_ABS64, elf.R_AARCH64_PREL32, elf.R_AARCH64_PREL64, elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26, elf.R_AARCH64_ADR_PREL_PG_HI21, elf.R_AARCH64_ADD_ABS_LO12_NC, elf.R_AARCH64_LDST8_ABS_LO12_NC, elf.R_AARCH64_LDST16_ABS_LO12_NC, elf.R_AARCH64_LDST32_ABS_LO12_NC, elf.R_AARCH64_LDST64_ABS_LO12_NC, elf.R_AARCH64_LDST128_ABS_LO12_NC, elf.R_AARCH64_ADR_GOT_PAGE, elf.R_AARCH64_LD64_GOT_LO12_NC:
		return true
	}
	return false
}

func (p *Plan) bind(images []*image, index map[string]string) error {
	if len(images) > 0 && images[0].effectiveMachine() == elf.EM_X86_64 {
		return p.bindAMD64(images, index)
	}
	if len(images) > 0 && images[0].effectiveMachine() != elf.EM_AARCH64 {
		return p.bindCross(images, index)
	}
	defined := map[string]bool{}
	undefined := map[string]bool{}
	weak := map[string]bool{}
	strong := map[string]bool{}
	for _, m := range images {
		for _, s := range m.symbols {
			if elf.ST_BIND(s.info) == elf.STB_LOCAL {
				continue
			}
			if s.sect != 0 {
				defined[s.name] = true
			} else {
				undefined[s.name] = true
				if elf.ST_BIND(s.info) == elf.STB_WEAK {
					weak[s.name] = true
				} else {
					strong[s.name] = true
				}
			}
		}
	}
	var names []string
	for name := range undefined {
		if !defined[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	bindings := map[string]Import{}
	missing := map[string]bool{}
	needed := p.requiredLibraries(images, index)
	var unresolved []string
	for _, name := range names {
		lib := index[name]
		if weak[name] && !strong[name] && !needed[lib] {
			missing[name] = true
			p.WeakZero = append(p.WeakZero, name)
			continue
		}
		if lib == "" {
			if weak[name] && !strong[name] {
				missing[name] = true
				p.WeakZero = append(p.WeakZero, name)
				continue
			}
			unresolved = append(unresolved, name)
			continue
		}
		b := Import{Local: fmt.Sprintf("%simport_%d", p.Namespace, len(p.Imports)), Remote: name, Library: lib}
		p.Imports = append(p.Imports, b)
		bindings[name] = b
	}
	if len(unresolved) != 0 {
		return &UnresolvedError{Names: unresolved}
	}
	for oi, m := range images {
		for si := range m.sections {
			s := &m.sections[si]
			if s.flags&elf.SHF_ALLOC == 0 {
				continue
			}
			var out []reloc
			for _, r := range s.relocs {
				if r.typ == elf.R_AARCH64_CONDBR19 || r.typ == elf.R_AARCH64_TSTBR14 {
					if err := resolveShortBranch(m, uint16(si), r); err != nil {
						return err
					}
					continue
				}
				if !supportedReloc(r.typ) {
					return fmt.Errorf("unsupported allocated ELF relocation %s in %s", r.typ, s.name)
				}
				if r.typ == elf.R_AARCH64_NONE {
					continue
				}
				sym := m.symbols[r.sym]
				if sym.sect == 0 && elf.ST_BIND(sym.info) == elf.STB_LOCAL {
					return fmt.Errorf("allocated relocation references discarded/invalid local symbol %s", sym.name)
				}
				if missing[sym.name] {
					if r.add != 0 {
						return fmt.Errorf("nonzero addend for unavailable weak import %s", sym.name)
					}
					switch r.typ {
					case elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26:
						// Preserve the NULL-address contract for optional weak
						// functions. Their GOT/data address is still zero. A
						// guarded direct call is unreachable; an unguarded call
						// branches to zero exactly as calling a NULL pointer would.
						name := fmt.Sprintf("%sweak_null_call_%d", p.Namespace, oi)
						idx := uint32(0)
						for j, q := range m.symbols {
							if q.name == name {
								idx = uint32(j)
								break
							}
						}
						if idx == 0 {
							code := make([]byte, 8)
							binary.LittleEndian.PutUint32(code, 0xaa1f03f0)     // mov x16, xzr
							binary.LittleEndian.PutUint32(code[4:], 0xd61f0200) // br x16
							sec := m.addSection(section{name: ".bao.weak_null_call", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 8, data: code})
							idx = m.addSymbol(name, sec, 0, 8)
							s = &m.sections[si]
						}
						r.sym = idx
						out = append(out, r)
						continue
					case elf.R_AARCH64_ABS64:
						if r.add != 0 || r.off+8 > uint64(len(s.data)) {
							return fmt.Errorf("unsupported missing-weak absolute pointer form")
						}
						binary.LittleEndian.PutUint64(s.data[r.off:], 0)
						continue
					case elf.R_AARCH64_ADR_GOT_PAGE, elf.R_AARCH64_LD64_GOT_LO12_NC: // ordinary load from an always-zero native cell
						zeroName := fmt.Sprintf("%sweak_zero_%d", p.Namespace, oi)
						idx := uint32(0)
						for j, q := range m.symbols {
							if q.name == zeroName {
								idx = uint32(j)
								break
							}
						}
						if idx == 0 {
							sec := m.addSection(section{name: ".bao.weak_zero", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8)})
							idx = m.addSymbol(zeroName, sec, 0, 8)
							s = &m.sections[si]
						}
						r.sym = idx
						if r.typ == elf.R_AARCH64_ADR_GOT_PAGE {
							r.typ = elf.R_AARCH64_ADR_PREL_PG_HI21
						} else {
							r.typ = elf.R_AARCH64_LDST64_ABS_LO12_NC
						}
						out = append(out, r)
						continue
					default:
						return fmt.Errorf("unsupported reference to unavailable weak import %s", sym.name)
					}
				}
				if b, ok := bindings[sym.name]; ok && r.typ == elf.R_AARCH64_ABS64 {
					if s.flags&elf.SHF_WRITE == 0 || r.off+8 > uint64(len(s.data)) {
						return fmt.Errorf("dynamic absolute pointer must be writable native data")
					}
					name := fmt.Sprintf("%sfixup_%d", p.Namespace, len(p.Fixups))
					m.addSymbol(name, uint16(si), r.off, 8)
					p.Fixups = append(p.Fixups, Fixup{Location: name, Import: b.Local, Addend: r.add})
					binary.LittleEndian.PutUint64(s.data[r.off:], 0)
					continue
				}
				if (r.typ == elf.R_AARCH64_ADR_GOT_PAGE || r.typ == elf.R_AARCH64_LD64_GOT_LO12_NC) && sym.sect != 0 {
					if r.off+4 > uint64(len(s.data)) {
						return fmt.Errorf("GOT instruction outside native code")
					}
					word := binary.LittleEndian.Uint32(s.data[r.off:])
					if r.typ == elf.R_AARCH64_ADR_GOT_PAGE {
						if word&0x9f000000 != 0x90000000 {
							return fmt.Errorf("unexpected local GOT ADRP")
						}
						r.typ = elf.R_AARCH64_ADR_PREL_PG_HI21
					} else {
						if word&0xffc00000 != 0xf9400000 {
							return fmt.Errorf("unexpected local GOT LDR")
						}
						binary.LittleEndian.PutUint32(s.data[r.off:], 0x91000000|word&0x003fffff)
						r.typ = elf.R_AARCH64_ADD_ABS_LO12_NC
					}
				}
				out = append(out, r)
			}
			m.sections[si].relocs = out
		}
		for i := range m.symbols {
			s := &m.symbols[i]
			if b, ok := bindings[s.name]; ok {
				s.name = b.Local
				s.info = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE)
			} else if missing[s.name] {
				s.name = "$d.bao.missing_weak"
				s.info = byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE)
			}
		}
	}
	return nil
}
