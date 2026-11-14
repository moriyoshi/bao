package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/format"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/translate"
)

// probeTLS emits the maintained consumer or an explicitly partial diagnostic
// stage. Link and execution evidence is collected by cmd/bao-verify.
// probeDylib translates a dylib through its anchor object; see translate.PrepareDylib.
func probeDylib(out, pkg, sdk string, symbols []string, dylib *translate.DylibImage, anchor translate.Object, before translate.Report, stderr io.Writer) error {
	return probeTLSImage(out, pkg, sdk, "elf", true, symbols, anchor.Data, []translate.Object{anchor}, before, stderr, dylib)
}

func probeTLS(out, pkg, sdk, container string, metadata bool, symbols []string, input []byte, objects []translate.Object, before translate.Report, stderr io.Writer) error {
	return probeTLSImage(out, pkg, sdk, container, metadata, symbols, input, objects, before, stderr, nil)
}

func probeTLSImage(out, pkg, sdk, container string, metadata bool, symbols []string, input []byte, objects []translate.Object, before translate.Report, stderr io.Writer, dylib *translate.DylibImage) error {
	if out == "" || len(objects) != 1 {
		return fmt.Errorf("probe-tls requires -o new-directory and one already-combined Mach-O object")
	}
	if container != "macho" && container != "elf" {
		return fmt.Errorf("unknown object container %q", container)
	}
	if !token.IsIdentifier(pkg) || pkg == "_" {
		return fmt.Errorf("invalid package name")
	}
	for _, s := range symbols {
		if !token.IsIdentifier(s) || s == "_" {
			return fmt.Errorf("invalid symbol name %q", s)
		}
		if dylib != nil {
			continue // checked against the dylib's exports
		}
		ok, err := translate.HasExport(objects[0], "_"+s)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("missing export %q", s)
		}
	}
	keep := symbols
	if dylib != nil {
		keep = nil
	}
	p, err := translate.LowerTLSKeeping(objects[0], keep)
	if err != nil {
		return err
	}
	p.Dylib = dylib
	if metadata {
		if sdk == "" {
			return fmt.Errorf("-runtime requires -sdk")
		}
		if err := p.PrepareRuntimeMetadata(); err != nil {
			return err
		}
	}
	if sdk != "" {
		if err := p.BindSystemImports(sdk); err != nil {
			return err
		}
	}
	if err := p.NormalizeAddends(); err != nil {
		return err
	}
	after, err := translate.Inspect(input, p.Objects)
	if err != nil {
		return err
	}
	if container == "elf" {
		for i := range p.Objects {
			b, err := translate.ELFContainer(p.Objects[i])
			if err != nil {
				return err
			}
			p.Objects[i].Data = b
		}
	}
	formatted, asmSource, err := darwinSource(&p, pkg, symbols, after.Unresolved, metadata)
	if err != nil {
		return err
	}
	artifacts := make(map[string]string)
	for i, o := range p.Objects {
		artifacts[fmt.Sprintf("native_%d_darwin_%s.syso", i, p.Arch)] = fmt.Sprintf("%x", sha256.Sum256(o.Data))
	}
	status := "TRANSLATED: run the explicit platform integration checks before distributing this artifact"
	if !metadata {
		status = "INCOMPLETE TLS PROBE: native initializer and unwind semantics are not initialized"
	} else if container == "macho" {
		status = "DIAGNOSTIC MACH-O: Go's reader does not propagate stronger native section alignment"
	}
	manifest := struct {
		Status              string                       `json:"status"`
		Namespace           string                       `json:"namespace"`
		Descriptors         int                          `json:"tls_descriptors"`
		Size                uint64                       `json:"tls_template_size"`
		Alignment           uint64                       `json:"tls_template_alignment"`
		AliasesRemoved      int                          `json:"text_aliases_coalesced"`
		BoundarySymbols     int                          `json:"section_boundary_symbols"`
		TextSectionsMerged  int                          `json:"text_sections_merged"`
		LocalSymbolsRenamed int                          `json:"local_symbols_renamed"`
		Imports             []translate.ImportBinding    `json:"imports,omitempty"`
		Fixups              []translate.PointerFixup     `json:"pointer_fixups,omitempty"`
		Unwind              []translate.UnwindSection    `json:"unwind_sections,omitempty"`
		Constructors        []translate.ConstructorTable `json:"constructor_tables,omitempty"`
		AddendsNormalized   int                          `json:"explicit_addends"`
		CompactFrames       int                          `json:"compact_frames_synthesized"`
		ObjectContainer     string                       `json:"object_container"`
		Artifacts           map[string]string            `json:"artifact_sha256"`
		Before              translate.Report             `json:"before"`
		After               translate.Report             `json:"after"`
	}{status, p.Namespace, p.Descriptors, p.TemplateSize, p.TemplateAlignment, p.AliasesRemoved, p.BoundarySymbols, p.TextSectionsMerged, p.LocalSymbolsRenamed, p.Imports, p.Fixups, p.Unwind, p.Constructors, p.AddendsNormalized, p.CompactFramesSynthesized, container, artifacts, before, after}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.Mkdir(out, 0o755); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(out)
		}
	}()
	for i, o := range p.Objects {
		if err := writeNew(filepath.Join(out, fmt.Sprintf("native_%d_darwin_%s.syso", i, p.Arch)), o.Data); err != nil {
			return err
		}
	}
	if dylib != nil {
		fmt.Fprintf(stderr, "planned dylib load: %d-byte image, %d rebases, %d binds, %d exports, %d FDEs, %d initializers\n", dylib.Size, len(dylib.Rebases), len(dylib.Binds), len(dylib.Exports), len(dylib.Unwind.FDEs), len(dylib.Initializers))
	}
	for name, data := range map[string][]byte{"symbols_darwin_" + p.Arch + ".go": formatted, "symbols_darwin_" + p.Arch + ".s": asmSource, "bao-manifest.json": append(b, '\n')} {
		if err := writeNew(filepath.Join(out, name), data); err != nil {
			return err
		}
	}
	complete = true
	fmt.Fprintf(stderr, "translated Darwin %s image: %d TLS descriptors, %d template bytes, %d compact frames; link and execution require separate verification\n", p.Arch, p.Descriptors, p.TemplateSize, p.CompactFramesSynthesized)
	return nil
}

// darwinSource generates the Go and assembler sources that bind a lowered
// Mach-O TLS probe. Per-entry data is emitted as tables so init has a fixed
// amount of code whatever the fixup, unwind or initializer table counts.
func darwinSource(p *translate.TLSProbe, pkg string, symbols, unresolved []string, metadata bool) ([]byte, []byte, error) {
	// Match Go's one-leading-underscore removal. A small explicit whitelist
	// prevents treating arbitrary data/framework symbols as libc functions.
	known := map[string]bool{}
	for _, name := range []string{"abort", "calloc", "free", "malloc", "memcpy", "posix_memalign", "pthread_key_create", "pthread_getspecific", "pthread_setspecific", "pthread_create", "pthread_join", "pthread_self", "pthread_main_np", "sched_yield", "write", "close", "pipe", "usleep", "__stack_chk_fail", "__stack_chk_guard", "_NSGetArgc", "_NSGetArgv", "_NSGetEnviron"} {
		known["_"+name] = true
	}
	var goSrc, asm strings.Builder
	extra := ""
	if p.Dylib != nil {
		extra = "\"os\"\n\"path/filepath\"\n\"sort\"\n\"strings\"\n"
	}
	fmt.Fprintf(&goSrc, "// Code generated by bao; DO NOT EDIT.\n// Darwin %s ABI; consumer uses Go's internal linker with cgo disabled.\n//go:build darwin && %s\n\npackage %s\n\nimport (\n%s\"github.com/ebitengine/purego\"\n\"runtime\"\n\"unsafe\"\n)\n", p.Arch, p.Arch, pkg, extra)
	asm.WriteString("// Code generated by bao probe-tls.\n#include \"textflag.h\"\n")
	for _, name := range unresolved {
		if known[name] {
			fmt.Fprintf(&goSrc, "\n//go:cgo_import_dynamic %s %s \"/usr/lib/libSystem.B.dylib\"\n", strings.TrimPrefix(name, "_"), strings.TrimPrefix(name, "_"))
		}
	}
	for _, b := range p.Imports {
		if strings.ContainsAny(b.Remote, " \t\r\n\"") {
			return nil, nil, fmt.Errorf("unsupported dynamic symbol spelling %q", b.Remote)
		}
		fmt.Fprintf(&goSrc, "\n//go:cgo_import_dynamic %s %s %q\n", b.Local, b.Remote, b.Library)
		if b.CallSymbol != "" {
			// A native ABI tail branch keeps LR, SP and every argument register.
			// Use an ordinary text symbol instead of Go's Mach-O PLT metadata
			// (whose stub width is hard-coded for x86 in this pinned linker).
			if p.Arch == "amd64" {
				fmt.Fprintf(&asm, "\nTEXT %s(SB),NOSPLIT|NOFRAME,$0-0\n\tMOVQ $%s(SB), R11\n\tJMP R11\n", b.CallSymbol, b.Local)
			} else {
				fmt.Fprintf(&asm, "\nTEXT %s(SB),NOSPLIT|NOFRAME,$0-0\n\tMOVD $%s(SB), R16\n\tJMP (R16)\n", b.CallSymbol, b.Local)
			}
		}
	}
	accessor := func(local, native string) {
		fmt.Fprintf(&goSrc, "\nfunc %s() uintptr\n", local)
		if p.Arch == "amd64" {
			fmt.Fprintf(&asm, "TEXT ·%s(SB),NOSPLIT,$0-8\n\tMOVQ $%s(SB), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n", local, native)
		} else {
			fmt.Fprintf(&asm, "TEXT ·%s(SB),NOSPLIT,$0-8\n\tMOVD $%s(SB), R0\n\tMOVD R0, ret+0(FP)\n\tRET\n", local, native)
		}
	}
	// Per-entry native addresses live in assembler tables walked by one loop
	// each in init; see writeAddressTable.
	addressTable := func(name string, symbols []string) {
		writeAddressTable(&asm, name, symbols)
		accessor(name, name+"<>")
	}
	if p.Dylib == nil {
		for i, s := range symbols {
			accessor(fmt.Sprintf("SymbolAddr%d", i), s)
		}
	}
	accessor("tlsTemplateAddress", p.TemplateSymbol)
	var dylibInit string
	configureArgs := fmt.Sprintf("tlsTemplateAddress(), %d, %d", p.TemplateSize, p.TemplateAlignment)
	if p.Dylib != nil {
		accessor("tlsAddress_thunk", p.RuntimeSymbol("tls_thunk"))
		accessor("nativeDylibConstructorCaller", p.RuntimeSymbol("runtime_call_constructor"))
		accessor("dylibImageBase", p.Dylib.BaseSymbol())
		dylibSource(&goSrc, p)
		// The dylib's TLS template is built from its fixed-up image.
		configureArgs = "dylibLoad()"
		dylibInit = "    dylibInitialize()\n"
	}
	for _, name := range []string{"configure", "live_blocks", "destroyed_blocks", "finalize_current_thread"} {
		accessor("tlsAddress_"+name, p.RuntimeSymbol("tls_"+name))
	}
	goSrc.WriteString(addressSliceHelper)
	var fixupInit strings.Builder
	if len(p.Fixups) != 0 {
		accessor("tlsAddress_patch_pointer", p.RuntimeSymbol("tls_patch_pointer"))
		fixupInit.WriteString("\n    var patch func(uintptr, uintptr)\n    purego.RegisterFunc(&patch, tlsAddress_patch_pointer())\n")
		// Import addresses stay accessor functions because a dynamic import is
		// reached through the linker's GOT. There is one per distinct import.
		seenImports := make(map[string]bool)
		locations := make([]string, len(p.Fixups))
		for i, f := range p.Fixups {
			locations[i] = f.Symbol
			if !seenImports[f.ImportLocal] {
				accessor("tlsImportAddress_"+f.ImportLocal, f.ImportLocal)
				seenImports[f.ImportLocal] = true
			}
		}
		addressTable("tlsFixupAddresses", locations)
		fmt.Fprintf(&goSrc, "\nvar tlsFixupImports = [...]struct{ address func() uintptr; addend uintptr }{%s}\n", goList(p.Fixups, func(f translate.PointerFixup) string {
			return fmt.Sprintf("{tlsImportAddress_%s,%#x}", f.ImportLocal, f.Addend)
		}))
		fmt.Fprintf(&fixupInit, "    for i, address := range baoAddresses(tlsFixupAddresses(), %d) { patch(address, tlsFixupImports[i].address()+tlsFixupImports[i].addend) }\n", len(p.Fixups))
	}
	var unwindInit, ctorInit strings.Builder
	if metadata {
		accessor("nativeIsMainThreadAddress", p.RuntimeSymbol("runtime_on_main_thread"))
		unwindInit.WriteString("    var isMain func() int32\n    purego.RegisterFunc(&isMain, nativeIsMainThreadAddress())\n    if isMain() == 0 { panic(\"native initializers require the startup OS thread\") }\n")
	}
	if len(p.Unwind) != 0 {
		if p.RegisterFrame != "" {
			accessor("nativeRegisterFrameAddress", p.RegisterFrame)
		} else {
			fmt.Fprintf(&goSrc, "\n//go:cgo_import_dynamic %sregister_frame __register_frame \"/usr/lib/libSystem.B.dylib\"\n", p.Namespace)
			accessor("nativeRegisterFrameAddress", p.Namespace+"register_frame")
		}
		unwindInit.WriteString("    var registerFrame func(uintptr)\n    purego.RegisterFunc(&registerFrame, nativeRegisterFrameAddress())\n")
		// FDE offsets of every section are flattened; nativeUnwindEnds marks
		// where each section's offsets stop.
		bases := make([]string, len(p.Unwind))
		var offsets []uint32
		ends := make([]int, len(p.Unwind))
		for i, section := range p.Unwind {
			bases[i] = section.Symbol
			offsets = append(offsets, section.FDEOffsets...)
			ends[i] = len(offsets)
		}
		addressTable("nativeUnwindBases", bases)
		fmt.Fprintf(&goSrc, "\nvar nativeUnwindOffsets = [...]uint32{%s}\n", goList(offsets, func(off uint32) string { return strconv.FormatUint(uint64(off), 10) }))
		fmt.Fprintf(&goSrc, "\nvar nativeUnwindEnds = [...]int{%s}\n", goList(ends, strconv.Itoa))
		fmt.Fprintf(&unwindInit, "    start := 0\n    for s, base := range baoAddresses(nativeUnwindBases(), %d) {\n        for _, off := range nativeUnwindOffsets[start:nativeUnwindEnds[s]] { registerFrame(base+uintptr(off)) }\n        start = nativeUnwindEnds[s]\n    }\n", len(p.Unwind))
	}
	if len(p.Constructors) != 0 {
		accessor("nativeReadPointerAddress", p.RuntimeSymbol("runtime_read_pointer"))
		accessor("nativeConstructorCallerAddress", p.RuntimeSymbol("runtime_call_constructor"))
		ctorInit.WriteString("    var readPointer func(uintptr) uintptr\n    var callConstructor func(uintptr)\n    purego.RegisterFunc(&readPointer, nativeReadPointerAddress())\n    purego.RegisterFunc(&callConstructor, nativeConstructorCallerAddress())\n")
		bases := make([]string, len(p.Constructors))
		for i, table := range p.Constructors {
			bases[i] = table.Symbol
		}
		addressTable("nativeConstructorsBases", bases)
		fmt.Fprintf(&goSrc, "\nvar nativeConstructorCounts = [...]uintptr{%s}\n", goList(p.Constructors, func(t translate.ConstructorTable) string { return strconv.FormatUint(t.Count, 10) }))
		fmt.Fprintf(&ctorInit, "    for t, base := range baoAddresses(nativeConstructorsBases(), %d) {\n    for i := uintptr(0); i < nativeConstructorCounts[t]; i++ {\n        fn := readPointer(base+i*8)\n        if fn == 0 { panic(\"null native initializer\") }\n        callConstructor(fn)\n    }\n    }\n", len(p.Constructors))
	}
	fmt.Fprintf(&goSrc, `
var tlsLive func() uint64
var tlsDestroyed func() uint64
var tlsFinalize func()

func init() {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
%s
%s
    var configure func(uintptr, uintptr, uintptr) int32
    purego.RegisterFunc(&configure, tlsAddress_configure())
    if status := configure(%s); status != 0 { panic(status) }
    purego.RegisterFunc(&tlsLive, tlsAddress_live_blocks())
    purego.RegisterFunc(&tlsDestroyed, tlsAddress_destroyed_blocks())
    purego.RegisterFunc(&tlsFinalize, tlsAddress_finalize_current_thread())
%s%s
}

// TLSLiveBlocks returns this image's currently allocated per-thread blocks.
func TLSLiveBlocks() uint64 { return tlsLive() }

// TLSDestroyedBlocks counts blocks released after their native TLS destructors.
func TLSDestroyedBlocks() uint64 { return tlsDestroyed() }

// TLSFinalizeCurrentThread runs this image's TLS destructors and frees storage
// on the calling OS thread. Call on the locked startup thread after native
// teardown, with no outstanding references to its TLS. Native pthread exits
// perform this automatically. This does not synchronize with other threads.
func TLSFinalizeCurrentThread() { tlsFinalize() }
`, fixupInit.String(), unwindInit.String(), configureArgs, dylibInit, ctorInit.String())
	formatted, err := format.Source([]byte(goSrc.String()))
	if err != nil {
		return nil, nil, err
	}
	return formatted, []byte(asm.String()), nil
}
