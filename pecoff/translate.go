package pecoff

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	_ "embed"
	"encoding/binary"
	"fmt"
	"go/token"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
)

type Options struct {
	Symbols    []string
	Imports    map[string]string
	StripDebug bool
	CXXRuntime string
	CRT        string
	// ImportLibraries are producer-named short-import libraries. Their IMPORT_CODE
	// records fill names that neither Imports nor the built-in catalog bind.
	// Import records embedded in native inputs never grant a binding.
	ImportLibraries [][]byte
	// MaxDataAlignment, when 32, lets read-only data sections requesting more
	// than Go's PE reader can provide link at 32 bytes. Zero rejects them.
	MaxDataAlignment uint32
}
type Import struct{ Local, Name, DLL string }
type Table struct {
	Symbol string
	Count  int
	Order  string
}

// CappedAlignment records a section linked below its requested alignment.
type CappedAlignment struct {
	Section            string `json:"section"`
	Requested, Applied uint32
}
type Alignment struct {
	Symbol string
	Bytes  uint32
}
type Plan struct {
	Arch, Namespace               string
	Objects                       [][]byte
	Exports                       []string
	Imports                       []Import
	Constructors, Unwind          []Table
	UnwindRoots                   []Table
	RemovedDebugSections          int
	RemovedBitcodeSections        int
	RemovedBitcodeBytes           uint64
	Alignments                    []Alignment
	TextAliasesFolded             int
	CappedAlignments              []CappedAlignment
	Runtime                       bool
	TLS                           TLSPlan
	CInitializers                 []Table
	PreTerminators, Terminators   []Table
	TLSCallbacks, TLSInitializers []Table
	DataImports                   []DataImport
	Notices                       map[string]string
}

//go:embed native/amd64/runtime.bin
var runtimeAMD64 []byte

//go:embed native/arm64/runtime.bin
var runtimeARM64 []byte

//go:embed native/LICENSE-BAO.txt
var runtimeLicense string

type TLSPlan struct {
	Symbol          string
	Size, Alignment uint32
	Accesses        int
}
type DataImport struct {
	Symbol, Name, DLL string
	Offset            uint32
	Addend            uint64
}

var systemImports = map[string]string{
	"GetCurrentProcessId": "kernel32.dll", "GetCurrentThreadId": "kernel32.dll",
	"GetTickCount64": "kernel32.dll", "QueryPerformanceCounter": "kernel32.dll",
	"Sleep":                     "kernel32.dll",
	"QueryPerformanceFrequency": "kernel32.dll", "RtlLookupFunctionEntry": "kernel32.dll",
	"RtlAddFunctionTable": "kernel32.dll", "RtlDeleteFunctionTable": "kernel32.dll",
	"GetProcessHeap": "kernel32.dll", "HeapAlloc": "kernel32.dll", "HeapFree": "kernel32.dll",
	"FlsAlloc": "kernel32.dll", "FlsGetValue": "kernel32.dll", "FlsSetValue": "kernel32.dll",
	"FlsFree":                "kernel32.dll",
	"RaiseFailFastException": "kernel32.dll", "CreateThread": "kernel32.dll", "WaitForSingleObject": "kernel32.dll", "CloseHandle": "kernel32.dll",
	"malloc": "ucrtbase.dll", "free": "ucrtbase.dll", "calloc": "ucrtbase.dll", "realloc": "ucrtbase.dll",
	"memcpy": "ucrtbase.dll", "memmove": "ucrtbase.dll", "memset": "ucrtbase.dll", "memcmp": "ucrtbase.dll",
	"_CxxThrowException": "vcruntime140.dll", "__CxxFrameHandler3": "vcruntime140.dll",
	"__CxxFrameHandler4": "vcruntime140_1.dll", "__C_specific_handler": "vcruntime140.dll",
	"__std_type_info_destroy_list": "vcruntime140.dll", "terminate": "vcruntime140.dll",
	"??_7type_info@@6B@":     "vcruntime140.dll",
	"__gxx_personality_seh0": "libstdc++-6.dll", "__cxa_allocate_exception": "libstdc++-6.dll", "__cxa_free_exception": "libstdc++-6.dll",
	"__cxa_throw": "libstdc++-6.dll", "__cxa_rethrow": "libstdc++-6.dll", "__cxa_begin_catch": "libstdc++-6.dll", "__cxa_end_catch": "libstdc++-6.dll",
	"_Unwind_Resume": "libgcc_s_seh-1.dll", "_ZTVN10__cxxabiv117__class_type_infoE": "libstdc++-6.dll",
	"_ZSt9terminatev":     "libstdc++-6.dll",
	"__cxa_guard_acquire": "libstdc++-6.dll", "__cxa_guard_release": "libstdc++-6.dll", "__cxa_guard_abort": "libstdc++-6.dll",
	"_ZTVN10__cxxabiv120__si_class_type_infoE": "libstdc++-6.dll", "_ZTVN10__cxxabiv121__vmi_class_type_infoE": "libstdc++-6.dll",
}

// Translate performs archive member selection without running a native linker.
// Unsupported runtime profiles and TLS access forms fail before publication.
func Translate(input []byte, opts Options) (*Plan, error) {
	members := []ar.Member{{Name: "input.obj", Data: input}}
	if bytes.HasPrefix(input, []byte("!<arch>\n")) {
		var err error
		members, err = ar.ParseCOFF(input)
		if err != nil {
			return nil, err
		}
	}
	if len(members) == 0 || len(opts.Symbols) == 0 {
		return nil, fmt.Errorf("COFF translation requires object members and selected exports")
	}
	sum := sha256.Sum256(input)
	p := &Plan{Namespace: fmt.Sprintf("bao_win_%x_", sum[:8])}
	objects := make([]*object, len(members))
	defs := map[string]int{}
	for i, m := range members {
		o, err := parse(m.Data)
		if err != nil {
			return nil, fmt.Errorf("COFF member %q: %w", m.Name, err)
		}
		objects[i] = o
		if err := o.lowerTLSDirectoryAnchor(); err != nil {
			return nil, fmt.Errorf("COFF member %q: %w", m.Name, err)
		}
		arch := "amd64"
		if o.machine == pe.IMAGE_FILE_MACHINE_ARM64 {
			arch = "arm64"
		}
		if p.Arch != "" && p.Arch != arch {
			return nil, fmt.Errorf("mixed COFF architectures")
		}
		p.Arch = arch
		for j := 0; j < len(o.symbols); {
			s := o.symbols[j]
			if s.StorageClass == 2 && s.SectionNumber > 0 {
				if _, ok := defs[o.names[j]]; !ok {
					defs[o.names[j]] = i
				}
			}
			j += 1 + int(s.NumberOfAuxSymbols)
		}
	}
	// MSVC C tentative definitions use COFF common symbols. Coalesce storage
	// once, retaining strong initialized definitions when one exists.
	common := map[string]uint32{}
	for _, o := range objects {
		for i := 0; i < len(o.symbols); {
			s := &o.symbols[i]
			if s.StorageClass == 2 && s.SectionNumber == 0 && s.Value != 0 {
				if s.Value > 64<<20 {
					return nil, fmt.Errorf("COFF common allocation exceeds 64 MiB")
				}
				if s.Value > common[o.names[i]] {
					common[o.names[i]] = s.Value
				}
				s.Value = 0
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
	if len(common) > 0 {
		o := &object{machine: objects[0].machine}
		names := make([]string, 0, len(common))
		for n := range common {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			if _, strong := defs[name]; strong {
				continue
			}
			size := common[name]
			if size < 32 {
				size = 32
			}
			o.sections = append(o.sections, section{name: ".bss", size: size, flags: pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | 0x600000})
			o.addSymbol(name, int16(len(o.sections)), 0)
			defs[name] = len(objects)
		}
		objects = append(objects, o)
		members = append(members, ar.Member{Name: "bao-common.obj"})
	}
	// The authored helper is linked only when a selected member needs lifecycle
	// or compiler TLS services. It is an ordinary COFF input, never extracted at runtime.
	indexWeakDefinitions(objects, defs)
	coordinateNativeFLS(objects, defs)
	runtimeData := runtimeAMD64
	if p.Arch == "arm64" {
		runtimeData = runtimeARM64
	}
	helper, err := parse(runtimeData)
	if err != nil {
		return nil, err
	}
	localizeRuntimeFallbacks(helper, defs)
	helperIndex := len(objects)
	objects = append(objects, helper)
	members = append(members, ar.Member{Name: "bao-runtime.obj", Data: runtimeData})
	for j := 0; j < len(helper.symbols); {
		s := helper.symbols[j]
		if s.StorageClass == 2 && s.SectionNumber > 0 {
			if _, ok := defs[helper.names[j]]; !ok {
				defs[helper.names[j]] = helperIndex
			}
		}
		j += 1 + int(s.NumberOfAuxSymbols)
	}
	if localIAT := localImportCells(objects, defs); len(localIAT) > 0 {
		// Keep the helper last: TLS aggregation stores its template there.
		for name, owner := range defs {
			if owner == helperIndex {
				defs[name] = helperIndex + len(localIAT)
			}
		}
		for j, cell := range localIAT {
			for i := 0; i < len(cell.symbols); i++ {
				if cell.symbols[i].SectionNumber > 0 {
					defs[cell.names[i]] = helperIndex + j
				}
			}
		}
		objects = append(objects[:helperIndex], localIAT...)
		objects = append(objects, helper)
		members = members[:helperIndex]
		for i := range localIAT {
			members = append(members, ar.Member{Name: fmt.Sprintf("bao-local-import-%d.obj", i)})
		}
		members = append(members, ar.Member{Name: "bao-runtime.obj", Data: runtimeData})
		helperIndex += len(localIAT)
	}
	selected := map[int]bool{}
	queue := []int{}
	for _, name := range opts.Symbols {
		i, ok := defs[name]
		if !ok {
			return nil, fmt.Errorf("selected COFF export %q is undefined", name)
		}
		function := false
		o := objects[i]
		for j := 0; j < len(o.symbols); {
			s := o.symbols[j]
			if o.names[j] == name && s.SectionNumber > 0 && int(s.SectionNumber) <= len(o.sections) && s.Type == 0x20 && o.sections[s.SectionNumber-1].flags&pe.IMAGE_SCN_CNT_CODE != 0 {
				function = true
			}
			j += 1 + int(s.NumberOfAuxSymbols)
		}
		if !token.IsIdentifier(name) || !function {
			return nil, fmt.Errorf("selected COFF export %q must be an undecorated C ABI function", name)
		}
		if !selected[i] {
			selected[i] = true
			queue = append(queue, i)
		}
		p.Exports = append(p.Exports, p.Namespace+name)
	}
	imports := map[string]string{}
	for n, d := range systemImports {
		imports[n] = d
	}
	switch opts.CRT {
	case "", "ucrt":
	case "msvcrt":
		for name, dll := range imports {
			if dll == "ucrtbase.dll" {
				imports[name] = "msvcrt.dll"
			}
		}
		delete(imports, "__acrt_iob_func")
	default:
		return nil, fmt.Errorf("unsupported Windows C runtime %q", opts.CRT)
	}
	// Fundamental GNU RTTI objects live in the C++ runtime, unlike descriptors
	// emitted for user-defined exception classes in the native object itself.
	for _, code := range []string{"v", "b", "c", "a", "h", "s", "t", "i", "j", "l", "m", "x", "y", "f", "d", "e", "w", "Dn", "Du", "Ds", "Di", "Pv", "PKv", "Pc", "PKc"} {
		imports["_ZTI"+code] = "libstdc++-6.dll"
	}
	switch opts.CXXRuntime {
	case "", "auto", "libstdc++":
	case "libc++":
		for n, d := range imports {
			if d == "libstdc++-6.dll" {
				imports[n] = "libc++.dll"
			}
			if d == "libgcc_s_seh-1.dll" {
				imports[n] = "libunwind.dll"
			}
		}
	default:
		return nil, fmt.Errorf("unsupported Windows C++ runtime %q", opts.CXXRuntime)
	}
	if opts.MaxDataAlignment != 0 && opts.MaxDataAlignment != 32 {
		return nil, fmt.Errorf("unsupported Windows maximum data alignment %d; only 32 is supported", opts.MaxDataAlignment)
	}
	libraryFunctions := map[string]bool{}
	for i, library := range opts.ImportLibraries {
		functions, err := importLibraryFunctions(library, objects[0].machine)
		if err != nil {
			return nil, fmt.Errorf("Windows import library %d: %w", i, err)
		}
		for name, dll := range functions {
			if _, bound := imports[name]; !bound {
				imports[name] = dll
				libraryFunctions[name] = true
			}
		}
	}
	for n, d := range opts.Imports {
		if !token.IsIdentifier(n) || !validDLL(d) {
			return nil, fmt.Errorf("invalid Windows system import %q=%q", n, d)
		}
		imports[n] = strings.ToLower(d)
	}
	needed := map[string]bool{}
	originalObjects := objects
	originalDefs := defs
	// Restart from pristine COFF whenever another archive member is extracted.
	// A newly selected LARGEST/NEWEST contribution may replace an earlier one;
	// weak aliases, TLS and unwind transformations must see the final winners.
	for {
		objects = cloneObjects(originalObjects)
		defs = make(map[string]int, len(originalDefs))
		for name, owner := range originalDefs {
			defs[name] = owner
		}
		if err := selectCOMDAT(objects, selected, defs, p.Namespace); err != nil {
			return nil, err
		}
		queue = queue[:0]
		for oi := range objects {
			if selected[oi] {
				queue = append(queue, oi)
			}
		}
		selectedCount := len(queue)
		needed = map[string]bool{}
		var unresolved ImportError
		mismatches := map[string]string{}
		strongScanned := map[int]bool{}
		for qi := 0; qi < len(queue); qi++ {
			// Discover ordinary references before weak aliases, so an archive member
			// selected by a strong dependency overrides a weak fallback independent of
			// symbol-table order in the referring object.
			for at := 0; at < selectedCount; at++ {
				owner := queue[at]
				if strongScanned[owner] {
					continue
				}
				strongScanned[owner] = true
				for _, sec := range objects[owner].sections {
					if debugSection(sec.name) || sec.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
						continue
					}
					for _, r := range sec.relocs {
						if int(r.SymbolTableIndex) >= len(objects[owner].symbols) {
							return nil, fmt.Errorf("invalid COFF relocation symbol index")
						}
						s := objects[owner].symbols[r.SymbolTableIndex]
						if s.StorageClass == 2 && s.SectionNumber == 0 {
							if i, ok := defs[objects[owner].names[r.SymbolTableIndex]]; ok && !selected[i] {
								selected[i] = true
								queue = append(queue, i)
							}
						}
					}
				}
			}
			if len(queue) != selectedCount {
				break
			}
			o := objects[queue[qi]]
			if err := validateDirectives(o, defs, mismatches); err != nil {
				return nil, err
			}
			if err := o.resolveAlternates(defs, selected); err != nil {
				return nil, err
			}
			for _, s := range o.sections {
				if s.name == ".drectve" {
					for _, word := range strings.Fields(string(s.data)) {
						k, v := coffDirective(word)
						if k == "include" {
							i := defs[v]
							if !selected[i] {
								selected[i] = true
								queue = append(queue, i)
							}
						}
					}
				}
			}
			if needsRuntime(o) && !selected[helperIndex] {
				selected[helperIndex] = true
				queue = append(queue, helperIndex)
				p.Runtime = true
			}
			if len(queue) != selectedCount {
				break
			}
			if err := o.resolveWeak(defs, selected); err != nil {
				return nil, err
			}
			for _, sec := range o.sections {
				if debugSection(sec.name) || sec.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
					continue
				}
				for _, r := range sec.relocs {
					if int(r.SymbolTableIndex) >= len(o.symbols) || o.names[r.SymbolTableIndex] == "" {
						return nil, fmt.Errorf("invalid COFF relocation symbol index")
					}
					s := o.symbols[r.SymbolTableIndex]
					name := o.names[r.SymbolTableIndex]
					if s.StorageClass != 2 || s.SectionNumber != 0 {
						continue
					}
					if i, ok := defs[name]; ok {
						if i == helperIndex {
							p.Runtime = true
						}
						if !selected[i] {
							selected[i] = true
							queue = append(queue, i)
						}
						continue
					}
					base := strings.TrimPrefix(name, "__imp_")
					if _, ok := imports[base]; !ok {
						unresolved.Undefined = append(unresolved.Undefined, name)
						continue
					}
					directCall := p.Arch == "arm64" && r.Type == 3
					if p.Arch == "amd64" && r.Type >= 4 && r.Type <= 9 && r.VirtualAddress > 0 && int(r.VirtualAddress) <= len(sec.data) {
						opcode := sec.data[r.VirtualAddress-1]
						directCall = opcode == 0xe8 || opcode == 0xe9
						// A tail call can also be a near Jcc (0F 8x rel32). A RIP-relative
						// ModRM byte is never in 0x80-0x8f, so this cannot be a data access.
						if r.VirtualAddress > 1 && sec.data[r.VirtualAddress-2] == 0x0f && opcode&0xf0 == 0x80 {
							directCall = true
						}
					}
					if !strings.HasPrefix(name, "__imp_") && s.Type != 0x20 && !directCall && !libraryFunctions[base] && !knownFunctionImport(base) && !knownDataImport(base) {
						unresolved.Bare = append(unresolved.Bare, name)
						continue
					}
					needed[name] = true
				}
			}
		}
		if len(queue) != selectedCount {
			continue
		}
		if unresolved.any() {
			unresolved.normalize()
			return nil, &unresolved
		}
		break
	}
	p.Runtime = selected[helperIndex]
	if p.Runtime {
		p.Notices = map[string]string{
			"LICENSE-BAO-WINDOWS.txt": runtimeLicense,
			"NOTICE-BAO-WINDOWS.txt":  "This package includes Bao's authored Windows lifecycle/TLS helper and call adapters.\nSPDX-License-Identifier: Apache-2.0\nSource and provenance: https://github.com/moriyoshi/bao/tree/main/pecoff/native\nThe helper was compiled at producer build time and is linked directly into this package's COFF .syso objects.\nThird-party runtimes may be linked from producer-supplied archives or imported from installed DLLs. Retain the matching third-party notices for bundled code.\n",
		}
	}
	for name := range needed {
		base := strings.TrimPrefix(name, "__imp_")
		if !knownDataImport(base) {
			remote := base
			if base == "__msvcrt_assert" {
				remote = "_assert"
			}
			if base == "fileno" {
				remote = "_fileno"
			}
			p.Imports = append(p.Imports, Import{p.Namespace + "imp_" + base, remote, imports[base]})
		}
	}
	selectedDefinitions := map[string]bool{}
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			if s.StorageClass == 2 && s.SectionNumber > 0 {
				name := o.names[i]
				if selectedDefinitions[name] {
					return nil, fmt.Errorf("duplicate selected non-coalescible COFF definition %s", name)
				}
				selectedDefinitions[name] = true
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
	sort.Slice(p.Imports, func(i, j int) bool {
		if p.Imports[i].Name != p.Imports[j].Name {
			return p.Imports[i].Name < p.Imports[j].Name
		}
		if p.Imports[i].DLL != p.Imports[j].DLL {
			return p.Imports[i].DLL < p.Imports[j].DLL
		}
		return p.Imports[i].Local < p.Imports[j].Local
	})
	// Multiple direct and dllimport references share one import cell.
	unique := p.Imports[:0]
	for _, im := range p.Imports {
		if len(unique) == 0 || unique[len(unique)-1].Local != im.Local {
			unique = append(unique, im)
		}
	}
	p.Imports = unique
	// Resolve private TLS section offsets before stripping/renumbering symbols.
	if err := prepareTLS(objects, selected, p); err != nil {
		return nil, err
	}
	exportNames := make(map[string]bool, len(opts.Symbols))
	for _, name := range opts.Symbols {
		exportNames[name] = true
	}
	p.TextAliasesFolded = foldTextAliases(objects, selected, exportNames)
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		{
			// Compiler identity/volatile metadata symbols cannot be loaded by
			// stock Go even when retaining the original debug section payloads.
			modified, err := o.encode()
			if err != nil {
				return nil, err
			}
			b, n, err := strip(modified, opts.StripDebug)
			if err != nil {
				return nil, err
			}
			o, err = parse(b)
			if err != nil {
				return nil, err
			}
			p.RemovedDebugSections += n.debug
			p.RemovedBitcodeSections += n.bitcode
			p.RemovedBitcodeBytes += n.bitcodeBytes
		}
		originalSymbols := len(o.symbols)
		if err := o.normalizeSections(); err != nil {
			return nil, err
		}
		if err := o.lowerReadOnlyREL32(); err != nil {
			return nil, err
		}
		if err := o.sortAMD64Unwind(); err != nil {
			return nil, err
		}
		if root := o.keepUnwindTargets(fmt.Sprintf("%sunwind_roots_%d", p.Namespace, oi)); root != nil {
			p.UnwindRoots = append(p.UnwindRoots, *root)
		}
		if err := o.fixDataImports(p, needed, imports, oi); err != nil {
			return nil, err
		}
		for si := range o.sections {
			s := &o.sections[si]
			if debugSection(s.name) || s.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 || s.size == 0 {
				continue
			}
			if s.name == ".drectve" {
				// Already interpreted and validated while selecting the closure.
				s.name = ".bao.drop"
				s.flags = pe.IMAGE_SCN_MEM_DISCARDABLE
				s.data = nil
				s.size = 0
				s.relocs = nil
				continue
			}
			// Go's special .xdata placement does not assign all compiler RTTI/EH
			// interior symbols an address. Keep the native bytes as ordinary data;
			// canonical amd64 .pdata still contributes to the PE exception directory.
			if s.name == ".xdata" {
				s.name = ".bao.xd"
			}
			if strings.HasPrefix(s.name, ".tls") || strings.HasPrefix(s.name, ".CRT$") && !supportedCRTSection(s.name) {
				return nil, fmt.Errorf("unsupported Windows native TLS/finalizer section %s", s.name)
			}
			alignment := uint32(1)
			a := (s.flags >> 20) & 15
			if a > 0 {
				alignment = 1 << (a - 1)
			}
			limit := uint32(32)
			if s.flags&pe.IMAGE_SCN_CNT_CODE != 0 {
				limit = 16
			}
			if alignment > limit && opts.MaxDataAlignment == limit && s.flags&(pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_EXECUTE|pe.IMAGE_SCN_MEM_WRITE) == 0 {
				p.CappedAlignments = append(p.CappedAlignments, CappedAlignment{s.name, alignment, limit})
				alignment = limit
			}
			if alignment > limit {
				return nil, fmt.Errorf("COFF section %s requests alignment %d beyond the checked stock-Go profile %d; -windows-max-data-alignment 32 accepts this for read-only data only", s.name, alignment, limit)
			}
			if s.flags&pe.IMAGE_SCN_CNT_CODE == 0 && !(p.Arch == "amd64" && (s.name == ".pdata" || s.name == ".xdata")) {
				// Go 1.26.11 infers data alignment up to 32 from section size.
				// Pad only the end so all original symbol/relocation offsets stay fixed.
				if s.size < alignment {
					s.size = alignment
					if len(s.data) > 0 {
						s.data = append(s.data, make([]byte, int(alignment)-len(s.data))...)
					}
				}
				name := fmt.Sprintf("%salign_%d_%d", p.Namespace, oi, si)
				o.addSymbol(name, int16(si+1), 0)
				p.Alignments = append(p.Alignments, Alignment{name, alignment})
			}
			if s.name == ".pdata" {
				width := uint32(12)
				if p.Arch == "arm64" {
					width = 8
				}
				if s.size%width != 0 {
					return nil, fmt.Errorf("invalid native Windows function-table size")
				}
				name := fmt.Sprintf("%spdata_%d_%d", p.Namespace, oi, si)
				o.addSymbol(name, int16(si+1), 0)
				mode := "PE exception directory"
				if p.Arch == "arm64" {
					mode = "RtlAddFunctionTable"
					s.name = ".bao.pd"
				}
				p.Unwind = append(p.Unwind, Table{name, int(s.size / width), mode})
			}
			if s.name == ".ctors" || s.name == ".dtors" || strings.HasPrefix(s.name, ".ctors.") || strings.HasPrefix(s.name, ".dtors.") || supportedCRTSection(s.name) {
				if _, err := gnuInitializerPriority(s.name); err != nil {
					return nil, err
				}
				if s.size%8 != 0 || uint64(len(s.data)) < uint64(s.size) {
					return nil, fmt.Errorf("unsupported Windows initializer table")
				}
				seen := map[uint32]bool{}
				for _, r := range s.relocs {
					pointerReloc := r.Type == 1 && p.Arch == "amd64" || r.Type == 14 && p.Arch == "arm64"
					if !pointerReloc || r.VirtualAddress%8 != 0 || r.VirtualAddress >= s.size || seen[r.VirtualAddress] {
						return nil, fmt.Errorf("unsupported Windows initializer pointer relocation")
					}
					seen[r.VirtualAddress] = true
				}
				for off := uint32(0); off < s.size; off += 8 {
					if !seen[off] && binary.LittleEndian.Uint64(s.data[off:]) != 0 && binary.LittleEndian.Uint64(s.data[off:]) != ^uint64(0) {
						return nil, fmt.Errorf("unrelocated native initializer pointer")
					}
				}
				name := fmt.Sprintf("%sctors_%d_%d", p.Namespace, oi, si)
				o.addSymbol(name, int16(si+1), 0)
				t := Table{name, int(s.size / 8), s.name}
				switch {
				case strings.HasPrefix(s.name, ".CRT$XI"):
					p.CInitializers = append(p.CInitializers, t)
				case strings.HasPrefix(s.name, ".CRT$XP"):
					p.PreTerminators = append(p.PreTerminators, t)
				case strings.HasPrefix(s.name, ".CRT$XT") || s.name == ".dtors" || strings.HasPrefix(s.name, ".dtors."):
					p.Terminators = append(p.Terminators, t)
				case strings.HasPrefix(s.name, ".CRT$XL"):
					p.TLSCallbacks = append(p.TLSCallbacks, t)
				case strings.HasPrefix(s.name, ".CRT$XD"):
					p.TLSInitializers = append(p.TLSInitializers, t)
				default:
					p.Constructors = append(p.Constructors, t)
				}
				s.name = ".bao.ct"
			}
			for ri := range s.relocs {
				r := &s.relocs[ri]
				if p.Arch == "amd64" && r.Type >= 5 && r.Type <= 9 {
					if uint64(r.VirtualAddress)+4 > uint64(len(s.data)) {
						return nil, fmt.Errorf("REL32_N outside native section")
					}
					value := int64(int32(binary.LittleEndian.Uint32(s.data[r.VirtualAddress:]))) - int64(r.Type-4)
					if value < -1<<31 || value > 1<<31-1 {
						return nil, fmt.Errorf("REL32_N addend overflow")
					}
					binary.LittleEndian.PutUint32(s.data[r.VirtualAddress:], uint32(value))
					r.Type = 4
				}
				width := uint64(4)
				if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type == 1 || o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && r.Type == 14 {
					width = 8
				}
				allowed := r.Type == 1 || r.Type == 2 || r.Type == 3 || r.Type == 4
				if p.Arch == "arm64" {
					allowed = r.Type == 1 || r.Type == 2 || r.Type == 3 || r.Type == 4 || r.Type == 6 || r.Type == 7 || r.Type == 14
				}
				if !allowed || uint64(r.VirtualAddress)+width > uint64(len(s.data)) {
					return nil, fmt.Errorf("unsupported/out-of-bounds Windows native relocation %#x in %s", r.Type, s.name)
				}
			}
		}
		for i := 0; i < len(o.symbols); {
			s := &o.symbols[i]
			name := o.names[i]
			if s.SectionNumber < -1 || s.SectionNumber == -1 && name != "@feat.00" {
				return nil, fmt.Errorf("unsupported COFF absolute/debug symbol %q", name)
			}
			if s.StorageClass == 2 && i < originalSymbols {
				if s.SectionNumber == 0 && s.Value != 0 {
					return nil, fmt.Errorf("COFF common symbol %s is unsupported", name)
				}
				if needed[name] && !knownDataImport(strings.TrimPrefix(name, "__imp_")) {
					base := strings.TrimPrefix(name, "__imp_")
					if strings.HasPrefix(name, "__imp_") {
						o.names[i] = p.Namespace + "imp_" + base
					} else {
						o.names[i] = p.Namespace + "stub_" + base
					}
				} else if !strings.HasPrefix(name, p.Namespace) {
					o.names[i] = p.Namespace + name
					if !token.IsIdentifier(name) {
						sum := sha256.Sum256([]byte(name))
						o.names[i] = fmt.Sprintf("%ssym_%x", p.Namespace, sum[:12])
					}
				}
			}
			if (s.StorageClass == 0 || s.StorageClass == 3 || s.StorageClass == 6) && s.SectionNumber > 0 && !(s.StorageClass == 3 && s.Type == 0 && strings.HasPrefix(name, ".")) {
				// MSVC reuses scoped label names such as $LN15 within a single
				// object. Go scopes locals only by object, so preserve identity
				// by symbol index, including labels used by ARM64 funclet SEH.
				o.names[i] = fmt.Sprintf("%slocal_%d_%d", p.Namespace, oi, i)
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
		o.uniqueSections()
		b, err := o.encode()
		if err != nil {
			return nil, err
		}
		p.Objects = append(p.Objects, b)
	}
	sort.SliceStable(p.Constructors, func(i, j int) bool {
		a, _ := gnuInitializerPriority(p.Constructors[i].Order)
		b, _ := gnuInitializerPriority(p.Constructors[j].Order)
		if a != b {
			return a < b
		}
		return p.Constructors[i].Order < p.Constructors[j].Order
	})
	for _, tables := range [][]Table{p.CInitializers, p.PreTerminators, p.Terminators, p.TLSCallbacks, p.TLSInitializers} {
		sort.SliceStable(tables, func(i, j int) bool { return tables[i].Order < tables[j].Order })
	}
	sort.SliceStable(p.Terminators, func(i, j int) bool {
		a, _ := gnuInitializerPriority(p.Terminators[i].Order)
		b, _ := gnuInitializerPriority(p.Terminators[j].Order)
		if a != b {
			return a > b
		}
		return p.Terminators[i].Order < p.Terminators[j].Order
	})
	return p, nil
}

// importLibraryFunctions reads a short-import library for one machine. Only
// by-name IMPORT_CODE records count: a data export cannot be reached through a
// code stub, and ordinal or undecorated forms need a name this model lacks.
func importLibraryFunctions(library []byte, machine uint16) (map[string]string, error) {
	members, err := ar.Parse(library)
	if err != nil {
		return nil, err
	}
	functions := map[string]string{}
	records := 0
	for _, m := range members {
		d := m.Data
		if len(d) < 20 || binary.LittleEndian.Uint16(d) != 0 || binary.LittleEndian.Uint16(d[2:]) != 0xffff || binary.LittleEndian.Uint16(d[6:]) != machine {
			continue
		}
		size := binary.LittleEndian.Uint32(d[12:])
		if uint64(size) > uint64(len(d)-20) {
			return nil, fmt.Errorf("member %q: truncated import record", m.Name)
		}
		fields := bytes.SplitN(d[20:20+size], []byte{0}, 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("member %q: malformed import record", m.Name)
		}
		records++
		kind := binary.LittleEndian.Uint16(d[18:])
		name, dll := string(fields[0]), string(fields[1])
		if kind&3 != 0 || kind>>2&7 != 1 || !token.IsIdentifier(name) || !validDLL(dll) {
			continue
		}
		if _, ok := functions[name]; !ok {
			functions[name] = strings.ToLower(dll)
		}
	}
	if records == 0 {
		return nil, fmt.Errorf("no short import records for machine %#x", machine)
	}
	return functions, nil
}

// ImportError lists every native reference that has no binding. Resolution
// finishes the selected object set first, so one run reports all of them.
type ImportError struct {
	Undefined []string // no native definition and no system DLL mapping
	Bare      []string // mapped, but not provably a function reference
}

func (e *ImportError) any() bool { return len(e.Undefined)+len(e.Bare) != 0 }

func (e *ImportError) normalize() {
	for _, names := range []*[]string{&e.Undefined, &e.Bare} {
		sort.Strings(*names)
		*names = slices.Compact(*names)
	}
}

func (e *ImportError) Error() string {
	var parts []string
	quote := func(names []string) string {
		quoted := make([]string, len(names))
		for i, name := range names {
			quoted[i] = strconv.Quote(name)
		}
		return strings.Join(quoted, ", ")
	}
	switch len(e.Undefined) {
	case 0:
	case 1:
		parts = append(parts, "undefined Windows native symbol "+quote(e.Undefined)+": supply an explicit system DLL mapping or a compatible native definition; CRT/TLS runtime support is not implicit")
	default:
		parts = append(parts, fmt.Sprintf("%d undefined Windows native symbols: %s: supply explicit system DLL mappings or compatible native definitions; CRT/TLS runtime support is not implicit", len(e.Undefined), quote(e.Undefined)))
	}
	if len(e.Bare) != 0 {
		parts = append(parts, "bare Windows import "+quote(e.Bare)+" must be a function; use an explicit dllimport declaration for IAT references")
	}
	return strings.Join(parts, "; ")
}

func validDLL(d string) bool {
	if !strings.HasSuffix(strings.ToLower(d), ".dll") || len(d) > 128 {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '+') {
			return false
		}
	}
	return !strings.Contains(d, "..")
}
