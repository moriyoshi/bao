package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/bindings"
	"github.com/moriyoshi/bao/pecoff"
	"github.com/moriyoshi/bao/toolchain"
)

func generateWindows(o nativeFlags, target toolchain.Target, input, output string, stdout, stderr io.Writer) error {
	if o.signatures != nil {
		for _, f := range o.signatures.Functions {
			if f.Name == "Shutdown" {
				return fmt.Errorf("Windows binding name Shutdown is reserved for lifecycle cleanup; choose another Go name")
			}
		}
	}
	b, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	imports := map[string]string{}
	for _, mapping := range o.windowsImports {
		name, dll, ok := strings.Cut(mapping, "=")
		if !ok {
			return fmt.Errorf("-windows-import requires SYMBOL=DLL.dll")
		}
		if _, ok := imports[name]; ok {
			return fmt.Errorf("duplicate Windows import %s", name)
		}
		imports[name] = dll
	}
	var importLibraries [][]byte
	var importLibraryRecords []map[string]string
	for _, path := range o.windowsImportLibraries {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		importLibraries = append(importLibraries, data)
		importLibraryRecords = append(importLibraryRecords, map[string]string{"name": filepath.Base(path), "sha256": fmt.Sprintf("%x", sha256.Sum256(data))})
	}
	options := pecoff.Options{Symbols: o.symbols, Imports: imports, StripDebug: o.stripDebug, CXXRuntime: o.windowsCXXRuntime, CRT: o.windowsCRT, ImportLibraries: importLibraries, MaxDataAlignment: uint32(o.windowsMaxDataAlignment)}
	translate := pecoff.Translate
	if pecoff.IsDLL(b) {
		translate = pecoff.TranslateDLL
	}
	p, err := translate(b, options)
	if err != nil {
		return err
	}
	if "windows/"+p.Arch != target.Name {
		return fmt.Errorf("COFF target changed during generation")
	}
	if err = os.Mkdir(output, 0755); err != nil {
		return err
	}
	formatted, asm, err := windowsSource(p, o.pkg)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "symbols_windows_"+p.Arch+".go"), formatted, 0644); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "symbols_windows_"+p.Arch+".s"), asm, 0644); err != nil {
		return err
	}
	artifacts := map[string]string{}
	if p.DLL != nil {
		name := "dll_windows_" + p.Arch + ".bin"
		if err = os.WriteFile(filepath.Join(output, name), p.DLL.Image, 0644); err != nil {
			return err
		}
		artifacts[name] = fmt.Sprintf("%x", sha256.Sum256(p.DLL.Image))
	}
	for i, data := range p.Objects {
		name := fmt.Sprintf("native_%d_windows_%s.syso", i, p.Arch)
		if err = os.WriteFile(filepath.Join(output, name), data, 0644); err != nil {
			return err
		}
		artifacts[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	if o.signatures != nil {
		if err = bindings.Generate(output, o.pkg, target.Name, *o.signatures, o.symbols); err != nil {
			return err
		}
	}
	for name, data := range p.Notices {
		if err := os.WriteFile(filepath.Join(output, name), []byte(data), 0644); err != nil {
			return err
		}
	}
	manifest := map[string]any{"target": target.Name, "profile": "Windows COFF; C ABI exports, CRT/TLS and native unwinding", "namespace": p.Namespace, "artifacts": artifacts, "imports": p.Imports, "data_imports": p.DataImports, "constructors": p.Constructors, "unwind_tables": p.Unwind, "tls": p.TLS, "crt_lifecycle": p.Runtime, "boundaries": "explicit quiescent Shutdown; exceptions remain in native code; declared system/runtime DLLs must be installed; GNU Rust std uses bundled matching unwind/CRT wrapper archives; managed FLS keys stay inside this image"}
	if len(importLibraryRecords) != 0 {
		manifest["windows_import_libraries"] = importLibraryRecords
	}
	if d := p.DLL; d != nil {
		manifest["windows_dll"] = map[string]any{"sha256": d.SHA256, "image_base": d.ImageBase, "image_size": d.ImageSize, "loaded_size": d.Size, "entry_point": d.Entry, "base_relocations": len(d.Relocations), "imports": d.Imports, "exports": d.Exports, "protections": d.Protections, "function_table": d.FunctionTable, "tls": d.TLS, "tls_array_loads_patched": len(d.Patches)}
		fmt.Fprintf(stderr, "planned DLL load: %d-byte image, %d base relocations, %d imports, %d exports, %d TLS array loads patched\n", d.ImageSize, len(d.Relocations), len(d.Imports), len(d.Exports), len(d.Patches))
	}
	if len(p.CappedAlignments) != 0 {
		manifest["windows_capped_alignments"] = p.CappedAlignments
		fmt.Fprintf(stderr, "linked %d read-only sections below their requested alignment; see windows_capped_alignments in bao-manifest.json\n", len(p.CappedAlignments))
	}
	for name, data := range map[string]any{"bao-manifest.json": manifest, "bao-debug.json": map[string]any{"stripped": o.stripDebug, "removed_sections": p.RemovedDebugSections, "bitcode_stripped": true, "removed_bitcode_sections": p.RemovedBitcodeSections, "removed_bitcode_bytes": p.RemovedBitcodeBytes, "original_sha256": fmt.Sprintf("%x", sha256.Sum256(b)), "runtime_unwind_preserved": true}} {
		buf, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(output, name), append(buf, '\n'), 0644); err != nil {
			return err
		}
	}
	if p.RemovedBitcodeSections != 0 {
		fmt.Fprintf(stderr, "Dropped %d bytes of embedded LLVM bitcode from %d sections\n", p.RemovedBitcodeBytes, p.RemovedBitcodeSections)
	}
	fmt.Fprintf(stderr, "translated %d Windows %s COFF objects; %d system imports, %d initializer tables, %d native unwind tables; verify execution on Windows separately\n", len(p.Objects), p.Arch, len(p.Imports), len(p.Constructors), len(p.Unwind))
	return nil
}

// windowsSource generates the Go and assembler sources that bind a translated
// COFF plan. Per-entry data is emitted as tables so init has a fixed amount of
// code whatever the section, import or unwind table counts.
func windowsSource(p *pecoff.Plan, pkg string) ([]byte, []byte, error) {
	var src, asm strings.Builder
	embed := ""
	if p.DLL != nil {
		embed = ";_ \"embed\""
	}
	fmt.Fprintf(&src, "// Code generated by Bao; DO NOT EDIT.\n//go:build windows && %s\npackage %s\nimport(\"syscall\";\"unsafe\";\"sync\";\"sort\"%s)\nvar _ = unsafe.Pointer(nil)\nvar _ = syscall.SyscallN\nvar _ = sort.Slice\nvar _ sync.Mutex\n", p.Arch, pkg, embed)
	asm.WriteString("// Code generated by Bao; DO NOT EDIT.\n#include \"textflag.h\"\n")
	accessor := func(name, symbol string) {
		fmt.Fprintf(&src, "func %s() uintptr\n", name)
		if p.Arch == "amd64" {
			fmt.Fprintf(&asm, "\nTEXT ·%s(SB),NOSPLIT,$0-8\n MOVQ $%s(SB),AX\n MOVQ AX,ret+0(FP)\n RET\n", name, symbol)
		} else {
			fmt.Fprintf(&asm, "\nTEXT ·%s(SB),NOSPLIT,$0-8\n MOVD $%s(SB),R0\n MOVD R0,ret+0(FP)\n RET\n", name, symbol)
		}
	}
	// Per-entry native addresses live in assembler tables walked by one loop
	// each in init; see writeAddressTable.
	addressTable := func(name string, symbols []string) {
		writeAddressTable(&asm, name, symbols)
		accessor(name, name+"<>")
	}
	tableSymbols := func(ts []pecoff.Table) []string {
		symbols := make([]string, len(ts))
		for i, t := range ts {
			symbols[i] = t.Symbol
		}
		return symbols
	}
	tableCount := func(t pecoff.Table) string { return strconv.Itoa(t.Count) }
	for i, symbol := range p.Exports {
		accessor(fmt.Sprintf("SymbolAddr%d", i), symbol)
	}
	if p.DLL != nil {
		dllSource(&src, p, accessor)
	}
	if len(p.Imports) > 0 {
		slots := make([]string, len(p.Imports))
		for i, im := range p.Imports {
			// Use an image-private writable import slot. With cgo enabled the Go
			// linker can represent dynamic imports as thunks instead of IAT data.
			fmt.Fprintf(&asm, "\nGLOBL %s(SB),NOPTR,$8\n", im.Local)
			slots[i] = im.Local
			stub := p.Namespace + "stub_" + strings.TrimPrefix(im.Local, p.Namespace+"imp_")
			if p.Arch == "amd64" {
				fmt.Fprintf(&asm, "\nTEXT %s(SB),NOSPLIT|NOFRAME,$0-0\n MOVQ $%s(SB),R11\n MOVQ 0(R11),R11\n JMP R11\n", stub, im.Local)
			} else {
				fmt.Fprintf(&asm, "\nTEXT %s(SB),NOSPLIT|NOFRAME,$0-0\n MOVD $%s(SB),R16\n MOVD 0(R16),R16\n JMP (R16)\n", stub, im.Local)
			}
		}
		addressTable("functionImportAddresses", slots)
		fmt.Fprintf(&src, "var functionImports = [...]struct{dll, name string}{%s}\n", goList(p.Imports, func(im pecoff.Import) string { return fmt.Sprintf("{%q,%q}", im.DLL, im.Name) }))
	}
	unwindRecords := 0
	if p.Arch == "arm64" && len(p.Unwind) > 0 {
		addressTable("unwindAddresses", tableSymbols(p.Unwind))
		fmt.Fprintf(&src, "var unwindCounts = [...]int{%s}\n", goList(p.Unwind, tableCount))
		for _, t := range p.Unwind {
			unwindRecords += t.Count
		}
	}
	if len(p.UnwindRoots) > 0 {
		addressTable("unwindRootsAddresses", tableSymbols(p.UnwindRoots))
	}
	if len(p.Alignments) > 0 {
		symbols := make([]string, len(p.Alignments))
		for i, a := range p.Alignments {
			symbols[i] = a.Symbol
		}
		addressTable("alignmentAddresses", symbols)
		fmt.Fprintf(&src, "var alignmentBytes = [...]uintptr{%s}\n", goList(p.Alignments, func(a pecoff.Alignment) string { return strconv.FormatUint(uint64(a.Bytes), 10) }))
	}
	if len(p.DataImports) > 0 {
		symbols := make([]string, len(p.DataImports))
		for i, im := range p.DataImports {
			symbols[i] = im.Symbol
		}
		addressTable("dataImportAddresses", symbols)
		fmt.Fprintf(&src, "var dataImports = [...]struct{dll, name string; offset, addend uintptr}{%s}\n", goList(p.DataImports, func(im pecoff.DataImport) string {
			return fmt.Sprintf("{%q,%q,%d,%d}", im.DLL, im.Name, im.Offset, im.Addend)
		}))
	}
	// walk holds baoEachPointer arguments for each nonempty pointer table kind.
	walk := map[string]string{}
	tables := map[string][]pecoff.Table{"constructor": p.Constructors, "cInitializer": p.CInitializers, "preTerminator": p.PreTerminators, "terminator": p.Terminators, "tlsCallback": p.TLSCallbacks, "tlsInitializer": p.TLSInitializers}
	// Fixed order keeps generated bytes deterministic.
	for _, kind := range []string{"constructor", "cInitializer", "preTerminator", "terminator", "tlsCallback", "tlsInitializer"} {
		ts := tables[kind]
		if len(ts) == 0 {
			continue
		}
		addressTable(kind+"Addresses", tableSymbols(ts))
		fmt.Fprintf(&src, "var %sCounts = [...]uintptr{%s}\n", kind, goList(ts, tableCount))
		reverse := "nil"
		if kind == "constructor" {
			// .ctors tables run from their last entry.
			fmt.Fprintf(&src, "var constructorReverse = [...]bool{%s}\n", goList(ts, func(t pecoff.Table) string { return strconv.FormatBool(strings.HasPrefix(t.Order, ".ctors")) }))
			reverse = "constructorReverse[:]"
		}
		walk[kind] = fmt.Sprintf("baoAddresses(%sAddresses(),%d),%sCounts[:],%s", kind, len(ts), kind, reverse)
	}
	src.WriteString(addressSliceHelper)
	src.WriteString(`
// baoEachPointer visits native pointer table entries in order, skipping null
// and -1 sentinels. A reversed table runs from its last entry.
func baoEachPointer(tables, counts []uintptr, reverse []bool, f func(uintptr)) {
	for t, table := range tables {
		for i := uintptr(0); i < counts[t]; i++ {
			j := i
			if reverse != nil && reverse[t] {
				j = counts[t] - 1 - i
			}
			if p := *(*uintptr)(unsafe.Pointer(table + j*8)); p != 0 && p != ^uintptr(0) {
				f(p)
			}
		}
	}
}
`)
	if p.Runtime {
		for _, name := range []string{"initialize", "shutdown", "finish", "tls_finalize", "tls_live", "tls_destroyed"} {
			accessor("runtimeAddress_"+name, p.Namespace+"bao_winrt_"+name)
		}
		if p.TLS.Symbol != "" {
			accessor("tlsTemplateAddress", p.TLS.Symbol)
		}
		src.WriteString(`
var nativeTLSCallbacks, nativeTLSInitializers []uintptr
var shutdownMutex sync.Mutex
var shutdownDone bool
// TLSFinalizeCurrentThread requires a locked OS thread and no remaining native TLS references.
// Windows-created native threads are cleaned automatically by FLS on thread exit.
func TLSFinalizeCurrentThread(){syscall.SyscallN(runtimeAddress_tls_finalize())}
func TLSLiveBlocks() uint64 {r,_,_:=syscall.SyscallN(runtimeAddress_tls_live());return uint64(r)}
func TLSDestroyedBlocks() uint64 {r,_,_:=syscall.SyscallN(runtimeAddress_tls_destroyed());return uint64(r)}
// Shutdown runs this package's TLS cleanup, registered exits and CRT terminators once.
// Stop and join native callers first. Go process exit does not call Shutdown.
func Shutdown(){shutdownMutex.Lock();defer shutdownMutex.Unlock();if shutdownDone{return}
 r,_,_:=syscall.SyscallN(runtimeAddress_shutdown());if int32(r)!=0{panic("native Windows shutdown requires quiescent native threads")}
`)
		for _, kind := range []string{"preTerminator", "terminator"} {
			if w, ok := walk[kind]; ok {
				fmt.Fprintf(&src, "baoEachPointer(%s,func(p uintptr){callConstructor(p)})\n", w)
			}
		}
		if p.DLL != nil && p.DLL.Entry != 0 {
			fmt.Fprintf(&src, "syscall.SyscallN(dllBase+%#x,dllBase,0,0)\n", p.DLL.Entry)
		}
		src.WriteString("syscall.SyscallN(runtimeAddress_finish());shutdownDone=true}\n")
	} else {
		src.WriteString("func Shutdown(){}\nfunc TLSFinalizeCurrentThread(){}\nfunc TLSLiveBlocks()uint64{return 0}\nfunc TLSDestroyedBlocks()uint64{return 0}\n")
	}
	// These functions are kept separate so execution controls can omit exactly
	// registration or initialization without changing the native input objects.
	if p.Arch == "arm64" && len(p.Unwind) > 0 {
		src.WriteString("var nativeFunctionTable uintptr\nfunc unwindAddressMerged()uintptr{return nativeFunctionTable}\n")
	}
	// A missing export must not stop programs that never call it. Native frames
	// cannot be unwound by a Go panic, so a call reports the name and exits.
	src.WriteString(`
func baoResolveImport(dll, name string) uintptr {
	proc := syscall.NewLazyDLL(dll).NewProc(name)
	if proc.Find() == nil {
		return proc.Addr()
	}
	return syscall.NewCallback(func() uintptr {
		print("native import ", name, " from ", dll, " is unavailable on this system\n")
		syscall.Exit(2)
		return 0
	})
}
`)
	src.WriteString("var registerFunctionTable = func(table uintptr,count uintptr,base uintptr) { r,_,_:=syscall.NewLazyDLL(\"kernel32.dll\").NewProc(\"RtlAddFunctionTable\").Call(table,count,base);if r==0{panic(\"native Windows unwind registration failed\")} }\nvar callConstructor=func(address uintptr){syscall.SyscallN(address)}\nfunc init(){\n")
	if len(p.Imports) > 0 {
		fmt.Fprintf(&src, "for i,slot:=range baoAddresses(functionImportAddresses(),%d){*(*uintptr)(unsafe.Pointer(slot))=baoResolveImport(functionImports[i].dll,functionImports[i].name)}\n", len(p.Imports))
	}
	if len(p.DataImports) > 0 {
		fmt.Fprintf(&src, "for i,slot:=range baoAddresses(dataImportAddresses(),%d){im:=dataImports[i];*(*uintptr)(unsafe.Pointer(slot+im.offset))=syscall.NewLazyDLL(im.dll).NewProc(im.name).Addr()+im.addend}\n", len(p.DataImports))
	}
	if len(p.Alignments) > 0 {
		fmt.Fprintf(&src, "for i,address:=range baoAddresses(alignmentAddresses(),%d){if address%%alignmentBytes[i]!=0 {panic(\"native COFF section alignment\")}}\n", len(p.Alignments))
	}
	if len(p.UnwindRoots) > 0 {
		fmt.Fprintf(&src, "for _,address:=range baoAddresses(unwindRootsAddresses(),%d){if address==0{panic(\"native Windows unwind roots unavailable\")}}\n", len(p.UnwindRoots))
	}
	if p.Arch == "arm64" && len(p.Unwind) > 0 {
		src.WriteString("base,_,_:=syscall.NewLazyDLL(\"kernel32.dll\").NewProc(\"GetModuleHandleW\").Call(0); if base==0{panic(\"native Windows image base unavailable\")}\n")
		fmt.Fprintf(&src, "functionRecords:=make([]uint64,0,%d)\nfor i,table:=range baoAddresses(unwindAddresses(),%d){functionRecords=append(functionRecords,unsafe.Slice((*uint64)(unsafe.Pointer(table)),unwindCounts[i])...)}\n", unwindRecords, len(p.Unwind))
		src.WriteString(`sort.Slice(functionRecords,func(i,j int)bool{return uint32(functionRecords[i])<uint32(functionRecords[j])})
for i:=1;i<len(functionRecords);i++{if uint32(functionRecords[i-1])==uint32(functionRecords[i]){panic("duplicate native Windows function table entry")}}
heap,_,_:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessHeap").Call()
nativeFunctionTable,_,_=syscall.NewLazyDLL("kernel32.dll").NewProc("HeapAlloc").Call(heap,0,uintptr(len(functionRecords))*8)
if nativeFunctionTable==0{panic("native Windows function table allocation failed")}
copy(unsafe.Slice((*uint64)(unsafe.Pointer(nativeFunctionTable)),len(functionRecords)),functionRecords)
registerFunctionTable(unwindAddressMerged(),uintptr(len(functionRecords)),base)
`)
	}
	if p.DLL != nil {
		src.WriteString("dllLoad()\n")
	}
	if p.Runtime {
		src.WriteString("moduleBase,_,_:=syscall.NewLazyDLL(\"kernel32.dll\").NewProc(\"GetModuleHandleW\").Call(0);if moduleBase==0{panic(\"native Windows image base unavailable\")}\n")
		if p.DLL != nil {
			// The DLL's TLS callbacks receive its own base as their module.
			src.WriteString("moduleBase=dllBase\nfor _,rva:=range dllTLSCallbacks{nativeTLSCallbacks=append(nativeTLSCallbacks,dllBase+uintptr(rva))}\n")
			if t := p.DLL.TLS; t != nil && t.End > t.Start {
				// The TLS initializer may hold relocated pointers: copy it from the loaded image.
				fmt.Fprintf(&src, "copy(unsafe.Slice((*byte)(unsafe.Pointer(tlsTemplateAddress())),%d),unsafe.Slice((*byte)(unsafe.Pointer(dllBase+%#x)),%d))\n", t.End-t.Start, t.Start, t.End-t.Start)
			}
		}
		for _, kind := range []string{"tlsCallback", "tlsInitializer"} {
			variable := "nativeTLSCallbacks"
			if kind == "tlsInitializer" {
				variable = "nativeTLSInitializers"
			}
			if w, ok := walk[kind]; ok {
				fmt.Fprintf(&src, "baoEachPointer(%s,func(p uintptr){%s=append(%s,p)})\n", w, variable, variable)
			}
		}
		src.WriteString("var cb,di uintptr;if len(nativeTLSCallbacks)>0{cb=uintptr(unsafe.Pointer(&nativeTLSCallbacks[0]))};if len(nativeTLSInitializers)>0{di=uintptr(unsafe.Pointer(&nativeTLSInitializers[0]))}\n")
		template := "uintptr(0)"
		if p.TLS.Symbol != "" {
			template = "tlsTemplateAddress()"
		}
		fmt.Fprintf(&src, "syscall.SyscallN(runtimeAddress_initialize(),%s,%d,%d,cb,uintptr(len(nativeTLSCallbacks)),di,uintptr(len(nativeTLSInitializers)),moduleBase)\n", template, p.TLS.Size, p.TLS.Alignment)
	}
	if p.DLL != nil && p.DLL.Entry != 0 {
		fmt.Fprintf(&src, "if r,_,_:=syscall.SyscallN(dllBase+%#x,dllBase,1,0);int32(r)==0{panic(\"bao: DllMain failed for DLL_PROCESS_ATTACH\")}\n", p.DLL.Entry)
	}
	if w, ok := walk["cInitializer"]; ok {
		fmt.Fprintf(&src, "baoEachPointer(%s,func(p uintptr){r,_,_:=syscall.SyscallN(p);if int32(r)!=0{panic(\"native Windows C initializer failed\")}})\n", w)
	}
	if w, ok := walk["constructor"]; ok {
		fmt.Fprintf(&src, "baoEachPointer(%s,func(p uintptr){callConstructor(p)})\n", w)
	}
	src.WriteString("}\n")
	formatted, err := format.Source([]byte(src.String()))
	if err != nil {
		return nil, nil, fmt.Errorf("Windows generated Go: %w", err)
	}
	return formatted, []byte(asm.String()), nil
}

// dllSource emits the loader for a DLL image: the Windows loader's steps,
// in its order, then the export table.
func dllSource(src *strings.Builder, p *pecoff.Plan, accessor func(string, string)) {
	d := p.DLL
	for _, name := range []string{"tls_array", "dll_configure", "pc_to_file_header", "cxx_throw"} {
		accessor("runtimeAddress_"+name, p.Namespace+"bao_winrt_"+name)
	}
	fmt.Fprintf(src, "\n//go:embed dll_windows_%s.bin\nvar dllImage string\nvar dllBase uintptr\n", p.Arch)
	for i, rva := range d.Selected {
		fmt.Fprintf(src, "func SymbolAddr%d() uintptr { return dllBase + %#x }\n", i, rva)
	}
	u32 := func(v uint32) string { return fmt.Sprintf("%#x", v) }
	fmt.Fprintf(src, "var dllRelocations = [...]uint32{%s}\n", goList(d.Relocations, u32))
	fmt.Fprintf(src, "var dllImports = [...]struct{slot uint32;dll,name string;ordinal uint16}{%s}\n", goList(d.Imports, func(im pecoff.DLLImport) string {
		return fmt.Sprintf("{%#x,%q,%q,%d}", im.Slot, im.DLL, im.Name, im.Ordinal)
	}))
	fmt.Fprintf(src, "var dllProtections = [...]struct{start,end,protect uint32}{%s}\n", goList(d.Protections, func(r pecoff.DLLRange) string { return fmt.Sprintf("{%#x,%#x,%#x}", r.Start, r.End, r.Protect) }))
	fmt.Fprintf(src, "var dllPatches = [...]struct{site,thunk,slot uint32;code,body string}{%s}\n", goList(d.Patches, func(t pecoff.DLLPatch) string {
		return fmt.Sprintf("{%#x,%#x,%#x,%q,%q}", t.Site, t.Thunk, t.Slot, t.Code, t.Body)
	}))
	var callbacks []uint32
	if d.TLS != nil {
		callbacks = d.TLS.Callbacks
	}
	fmt.Fprintf(src, "var dllTLSCallbacks = [...]uint32{%s}\n", goList(callbacks, u32))
	var names []string
	var rvas []uint32
	for _, e := range d.Exports {
		names, rvas = append(names, e.Name), append(rvas, e.RVA)
	}
	fmt.Fprintf(src, "var dllExportNames = [...]string{%s}\nvar dllExportRVAs = [...]uint32{%s}\n", goList(names, strconv.Quote), goList(rvas, u32))
	width := uint32(12)
	if p.Arch == "arm64" {
		width = 8
	}
	fmt.Fprintf(src, `
func dllProc(name string) *syscall.LazyProc { return syscall.NewLazyDLL("kernel32.dll").NewProc(name) }

// dllResolve binds one DLL import as the Windows loader would. A missing
// import fails initialization, as loading the DLL would.
func dllResolve(lib, name string, ordinal uint16) uintptr {
	h, err := syscall.LoadLibrary(lib)
	if err != nil { panic("bao: DLL import library " + lib + ": " + err.Error()) }
	var address uintptr
	if name == "" {
		address, _, _ = dllProc("GetProcAddress").Call(uintptr(h), uintptr(ordinal))
	} else {
		address, err = syscall.GetProcAddress(h, name)
	}
	if address == 0 { panic("bao: DLL import " + lib + "!" + name + " is unavailable") }
	return address
}

// dllLoad maps the DLL into private memory: base relocations, imports,
// TLS array loads, page protections, then its function table.
func dllLoad() {
	const size, preferred = %d, %#x
	base, _, _ := dllProc("VirtualAlloc").Call(0, size, 0x3000, 0x04)
	if base == 0 { panic("bao: DLL image allocation failed") }
	image := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	copy(image, dllImage)
	for _, rva := range dllRelocations { *(*uint64)(unsafe.Pointer(&image[rva])) += uint64(base) - preferred }
	originals := map[string]uintptr{}
	for _, im := range dllImports {
		address := dllResolve(im.dll, im.name, im.ordinal)
		switch im.name {
		case "RtlPcToFileHeader":
			originals[im.name], address = address, runtimeAddress_pc_to_file_header()
		case "_CxxThrowException":
			originals[im.name], address = address, runtimeAddress_cxx_throw()
		}
		*(*uintptr)(unsafe.Pointer(&image[im.slot])) = address
	}
	if originals["RtlPcToFileHeader"] == 0 { originals["RtlPcToFileHeader"] = syscall.NewLazyDLL("ntdll.dll").NewProc("RtlPcToFileHeader").Addr() }
	syscall.SyscallN(runtimeAddress_dll_configure(), base, size, originals["RtlPcToFileHeader"], originals["_CxxThrowException"])
	for _, t := range dllPatches {
		copy(image[t.thunk:], t.body)
		*(*uintptr)(unsafe.Pointer(&image[t.slot])) = runtimeAddress_tls_array()
		copy(image[t.site:], t.code)
	}
	for _, r := range dllProtections {
		var old uint32
		if ok, _, _ := dllProc("VirtualProtect").Call(base+uintptr(r.start), uintptr(r.end-r.start), uintptr(r.protect), uintptr(unsafe.Pointer(&old))); ok == 0 { panic("bao: DLL page protection failed") }
	}
	process, _, _ := dllProc("GetCurrentProcess").Call()
	dllProc("FlushInstructionCache").Call(process, base, size)
	dllBase = base
`, d.Size, d.ImageBase)
	if n := (d.FunctionTable.End - d.FunctionTable.Start) / width; n != 0 {
		fmt.Fprintf(src, "registerFunctionTable(base+%#x, %d, base)\n", d.FunctionTable.Start, n)
	}
	src.WriteString(`}

// SharedObjectExport returns the run-time address of a DLL export.
func SharedObjectExport(name string) (uintptr, bool) {
	i := sort.SearchStrings(dllExportNames[:], name)
	if i == len(dllExportNames) || dllExportNames[i] != name { return 0, false }
	return dllBase + uintptr(dllExportRVAs[i]), true
}

// SharedObjectExports lists the DLL's exported names, sorted.
func SharedObjectExports() []string { return append([]string(nil), dllExportNames[:]...) }
`)
}
