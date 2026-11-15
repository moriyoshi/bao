package main

import (
	"bytes"
	"debug/macho"
	"debug/pe"
	"os"
	"path/filepath"
	"strings"
)

// darwinSymbolEdits builds testdata/symedit_*.c into archives and edits them
// with bao build: wrapped calls (including one inside the defining object),
// private prefixes for two link archives that vendor the same symbols, and
// keep-global on the primary archive, which is partially linked on its own
// first. The negative control builds without prefixes, which ld64 rejects as
// duplicate symbols.
func (h *harness) darwinSymbolEdits(arch, sdk string) {
	ldarch := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[arch]
	dir := filepath.Join(h.dst, "symedit")
	require(os.Mkdir(dir, 0o755))
	compile := func(name, source string, defines ...string) string {
		object := filepath.Join(dir, name+".o")
		args := append([]string{"xcrun", "clang", "-arch", ldarch, "-O2", "-fno-inline", "-fno-builtin", "-mmacosx-version-min=11.0", "-c", "-o", object}, defines...)
		h.run("symedit-cc-"+name+".log", dir, nil, append(args, filepath.Join(h.root, "testdata", source))...)
		return object
	}
	archive := func(name string, objects ...string) string {
		path := filepath.Join(dir, name)
		h.run("symedit-ar-"+name+".log", dir, nil, append([]string{"xcrun", "ar", "rcs", path}, objects...)...)
		return path
	}
	core := archive("libcore.a", compile("core", "symedit_core.c"), compile("glue", "symedit_glue.c"))
	a := archive("liba.a", compile("vendor_a", "symedit_vendor.c", "-DCOMPONENT=a", "-DCOUNTER=1"))
	b := archive("libb.a", compile("vendor_b", "symedit_vendor.c", "-DCOMPONENT=b", "-DCOUNTER=2"))
	build := []string{"build", "-target", h.target, "-sdk", sdk, "-symbol", "bao_symedit_wrapped", "-symbol", "bao_symedit_components", "-wrap", "target", "-wrap", "strlen", "-link-archive", a, "-link-archive", b}
	app := filepath.Join(h.dst, "symedit-app")
	require(os.Mkdir(app, 0o755))
	edits := []string{"-prefix-symbols", a + "=a_", "-prefix-symbols", b + "=b_", "-redefine-sym", "a_entry=a_entry", "-redefine-sym", "b_entry=b_entry",
		"-wildcard", "-keep-global-symbol", core + "=bao_symedit_*", "-o", filepath.Join(app, "native")}
	h.run("symedit-producer.log", h.root, nil, append(append(append([]string{h.bao}, build...), edits...), core)...)
	out := string(read(filepath.Join(h.dst, "symedit-producer.log")))
	check(strings.Contains(out, "Combining the input before changing its symbol bindings"), "keep-global did not partially link the primary archive first")
	h.module(app, "bao-symedit-check", "")
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(symbolEditsConsumer), 0o644))
	exe := filepath.Join(h.dst, "symedit-check")
	h.consumer("symedit-build.log", app, h.goTool, "build", "-o", exe, ".")
	got, err := h.command("symedit-run.log", h.root, nil, exe)
	check(err == nil && strings.Contains(string(got), "PASS: symbol edits"), "symbol edit consumer failed: %v\n%s", err, got)
	got, err = h.command("symedit-negative-producer.log", h.root, nil, append(append([]string{h.bao}, build...), "-o", filepath.Join(h.dst, "symedit-negative"), core)...)
	check(err != nil && strings.Contains(string(got), "duplicate symbol"), "building without prefixes did not fail on duplicate symbols: %v\n%s", err, got)
	h.darwinSectionEdits(dir, compile("section", "symedit_section.c", "-g"), sdk)
	h.results["darwin_symbol_edits"] = map[string]any{"status": "PASS", "checks": "lld-style wrap including a call inside the defining object and __real_ bound to it, wrapped libSystem strlen, private prefixes for two archives vendoring the same symbols with identity-renamed entry points, keep-global wildcard on a partially linked primary archive; negative control without prefixes fails on duplicate symbols; section edits: __DWARF sections removed and -add-symbol aliases at the start of a function's section (objcopy) and at the function itself (build) called natively, with removal of that code section refused"}
}

// darwinSectionEdits removes the debug sections of testdata/symedit_section.c
// and adds an alias of its function, first with bao objcopy at the start of
// the function's section, whose result it inspects, then in a bao build at
// the function itself (@bao_symedit_section), whose consumer calls both names. The negative control removes the function's section, which the
// object's unwind and debug data describe.
func (h *harness) darwinSectionEdits(dir, object, sdk string) {
	f, err := macho.Open(object)
	require(err)
	section, offset := "", ^uint64(0)
	debug := 0
	for _, s := range f.Symtab.Syms {
		if s.Name == "_bao_symedit_section" && s.Sect > 0 {
			sec := f.Sections[s.Sect-1]
			section, offset = sec.Seg+","+sec.Name, s.Value-sec.Addr
		}
	}
	for _, s := range f.Sections {
		if s.Seg == "__DWARF" {
			debug++
		}
	}
	f.Close()
	check(offset == 0 && debug > 0, "section fixture: bao_symedit_section at %s+%d with %d debug sections", section, offset, debug)
	add := "bao_symedit_alias=" + section + ":0,function"
	edited := filepath.Join(dir, "section-edited.o")
	h.run("symedit-section-objcopy.log", h.root, nil, h.bao, "objcopy", "-wildcard", "-remove-section", "__DWARF,*", "-add-symbol", add, object, edited)
	f, err = macho.Open(edited)
	require(err)
	addrs := map[string]uint64{}
	for _, s := range f.Symtab.Syms {
		if s.Sect > 0 && f.Sections[s.Sect-1].Seg+","+f.Sections[s.Sect-1].Name == section {
			addrs[s.Name] = s.Value
		}
	}
	for _, s := range f.Sections {
		check(s.Seg != "__DWARF", "objcopy kept %s,%s", s.Seg, s.Name)
	}
	f.Close()
	alias, ok := addrs["_bao_symedit_alias"]
	check(ok && alias == addrs["_bao_symedit_section"], "objcopy alias %v does not match the function: %v", ok, addrs)
	lib := filepath.Join(dir, "libsection.a")
	h.run("symedit-ar-libsection.a.log", dir, nil, "xcrun", "ar", "rcs", lib, object)
	app := filepath.Join(h.dst, "symedit-section-app")
	require(os.Mkdir(app, 0o755))
	build := []string{h.bao, "build", "-target", h.target, "-sdk", sdk, "-symbol", "bao_symedit_section", "-symbol", "bao_symedit_alias", "-wildcard"}
	h.run("symedit-section-producer.log", h.root, nil, append(build, "-remove-section", lib+"=__DWARF,*", "-add-symbol", lib+"=bao_symedit_alias=@bao_symedit_section:0,function", "-o", filepath.Join(app, "native"), lib)...)
	h.module(app, "bao-symedit-section-check", "")
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(sectionEditsConsumer), 0o644))
	exe := filepath.Join(h.dst, "symedit-section-check")
	h.consumer("symedit-section-build.log", app, h.goTool, "build", "-o", exe, ".")
	got, err := h.command("symedit-section-run.log", h.root, nil, exe)
	check(err == nil && strings.Contains(string(got), "PASS: section edits"), "section edit consumer failed: %v\n%s", err, got)
	got, err = h.command("symedit-section-negative-producer.log", h.root, nil, append(build, "-remove-section", lib+"="+section, "-o", filepath.Join(h.dst, "symedit-section-negative"), lib)...)
	check(err != nil && strings.Contains(string(got), "cannot remove Mach-O section "+section), "removing the function's section was not refused: %v\n%s", err, got)
}

const sectionEditsConsumer = `package main

import (
	"fmt"
	"os"

	"bao-symedit-section-check/native"
	"github.com/ebitengine/purego"
)

func main() {
	direct, _, _ := purego.SyscallN(native.SymbolAddr0())
	alias, _, _ := purego.SyscallN(native.SymbolAddr1())
	fmt.Println("direct:", direct, "alias:", alias)
	if direct != 7 || alias != 7 || native.SymbolAddr0() != native.SymbolAddr1() {
		os.Exit(1)
	}
	fmt.Println("PASS: section edits")
}
`

const symbolEditsConsumer = `package main

import (
	"fmt"
	"os"

	"bao-symedit-check/native"
	"github.com/ebitengine/purego"
)

func main() {
	wrapped, _, _ := purego.SyscallN(native.SymbolAddr0())
	components, _, _ := purego.SyscallN(native.SymbolAddr1())
	fmt.Println("wrapped:", wrapped, "components:", components)
	// 102/1020/1003 once wrapped; each vendored strlen call is wrapped too.
	if wrapped != 103021003 || components != 11012 {
		os.Exit(1)
	}
	fmt.Println("PASS: symbol edits")
}
`

// windowsSymbolEdits checks the symbol edits on COFF with the suite's
// compiler driver: the same wrap, prefix and keep-global build as
// darwinSymbolEdits, run natively, with the same negative control. Bao selects
// COFF archive members itself, so keep-global applies per member there.
func (h *harness) windowsSymbolEdits(arch string) {
	dir := filepath.Join(h.dst, "symedit")
	require(os.Mkdir(dir, 0o755))
	compile := func(name, source string, defines ...string) string {
		object := filepath.Join(dir, name+".obj")
		input := filepath.Join(h.root, "testdata", source)
		args := h.windowsCompile(h.windowsCC, input, object, arch, false)
		// Keep calls as calls, and put each function in its own section:
		// COFF assemblers resolve calls within one section without a
		// relocation, which a wrap could not redirect.
		extra := []string{"-fno-inline", "-fno-builtin", "-ffunction-sections"}
		switch h.windowsDriver {
		case "msvc":
			extra = []string{"/Ob0", "/Oi-", "/Gy"}
		case "clang-cl":
			extra = []string{"/Ob0", "/Gy", "/clang:-fno-builtin"}
		}
		if source == "symedit_section.c" {
			// One function in the object's only code section, whose name
			// is then unique. clang-cl defaults to a COMDAT section per
			// function beside an empty .text.
			extra = nil
			if h.windowsDriver == "msvc" || h.windowsDriver == "clang-cl" {
				extra = []string{"/Gy-"}
			}
		}
		at := len(args)
		for i, a := range args {
			if a == input {
				at = i
				if i > 0 && args[i-1] == "--" {
					at--
				}
			}
		}
		args = append(args[:at:at], append(append(extra, defines...), args[at:]...)...)
		h.run("symedit-cc-"+name+".log", h.root, nil, args...)
		return object
	}
	archive := func(name string, objects ...string) string {
		path := filepath.Join(dir, name)
		h.run("symedit-ar-"+name+".log", h.root, nil, append([]string{h.windowsAR, "rcS", path}, objects...)...)
		return path
	}
	core := archive("libcore.a", compile("core", "symedit_core.c"), compile("glue", "symedit_glue.c"))
	a := archive("liba.a", compile("vendor_a", "symedit_vendor.c", "-DCOMPONENT=a", "-DCOUNTER=1"))
	b := archive("libb.a", compile("vendor_b", "symedit_vendor.c", "-DCOMPONENT=b", "-DCOUNTER=2"))
	signatures := filepath.Join(dir, "signatures.json")
	require(os.WriteFile(signatures, []byte(symbolEditsSignatures), 0o644))
	build := []string{h.bao, "build", "-target", h.target, "-bindings", signatures, "-wrap", "target", "-wrap", "strlen", "-link-archive", a, "-link-archive", b}
	app := filepath.Join(h.dst, "symedit-app")
	require(os.Mkdir(app, 0o755))
	edits := []string{"-prefix-symbols", a + "=a_", "-prefix-symbols", b + "=b_", "-redefine-sym", "a_entry=a_entry", "-redefine-sym", "b_entry=b_entry",
		"-wildcard", "-keep-global-symbol", core + "=bao_symedit_*", "-o", filepath.Join(app, "native")}
	h.run("symedit-producer.log", h.root, nil, append(append(build, edits...), core)...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-windows-symedit\ngo 1.26.0\n"), 0o644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(windowsSymbolEditsConsumer), 0o644))
	exe := filepath.Join(h.dst, "symedit.exe")
	h.run("symedit-build.log", app, h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch}), h.goTool, "build", "-o", exe, ".")
	// GNU as for PE emits calls to a function defined in the same object
	// against its section rather than its symbol, so no symbol edit can
	// redirect them, as with lld-link -wrap: only the strlen import and
	// references between objects are wrapped.
	want := "wrapped: 103021003 components: 11012"
	if h.windowsDriver == "mingw" {
		want = "wrapped: 2021003 components: 11012"
	}
	out, err := h.command("symedit-run.log", h.root, nil, h.windowsExecute(exe)...)
	check(err == nil && strings.Contains(string(out), want+"\n"), "Windows symbol edit consumer did not print %q: %v\n%s", want, err, out)
	out, err = h.command("symedit-negative-producer.log", h.root, nil, append(build, "-o", filepath.Join(h.dst, "symedit-negative"), core)...)
	check(err != nil && strings.Contains(string(out), "duplicate"), "building without prefixes did not fail on duplicate definitions: %v\n%s", err, out)
	h.windowsSectionEdits(dir, compile("section", "symedit_section.c"), arch)
	h.results["windows_symbol_edits"] = map[string]any{"status": "PASS", "driver": h.windowsDriver, "checks": "lld-style wrap including a call inside the defining object (except with MinGW GCC, whose assembler calls same-object functions through their section) and __real_ bound to it, wrapped UCRT strlen, private prefixes for two archives vendoring the same symbols with identity-renamed entry points, keep-global wildcard per member; negative control without prefixes fails on duplicate definitions; section edits: debug sections removed and -add-symbol aliases at the start of a function's section (objcopy) and at the function itself (build) called natively, with removal of that code section refused"}
}

// windowsSectionEdits is darwinSectionEdits for COFF: CodeView or DWARF
// debug sections go, whose names all start with .debug.
func (h *harness) windowsSectionEdits(dir, object, arch string) {
	sections := func(path string) (map[string]string, map[string]uint32, int) {
		f, err := pe.NewFile(bytes.NewReader(read(path)))
		require(err)
		defer f.Close()
		where, values := map[string]string{}, map[string]uint32{}
		for i := 0; i < len(f.COFFSymbols); i++ {
			s := f.COFFSymbols[i]
			name, err := s.FullName(f.StringTable)
			require(err)
			if s.SectionNumber > 0 && s.StorageClass == 2 {
				where[name], values[name] = f.Sections[s.SectionNumber-1].Name, s.Value
			}
			i += int(s.NumberOfAuxSymbols)
		}
		debug := 0
		for _, s := range f.Sections {
			if strings.HasPrefix(s.Name, ".debug") {
				debug++
			}
		}
		return where, values, debug
	}
	where, values, debug := sections(object)
	section := where["bao_symedit_section"]
	check(section != "" && values["bao_symedit_section"] == 0 && debug > 0, "section fixture: bao_symedit_section at %q+%d with %d debug sections", section, values["bao_symedit_section"], debug)
	add := "bao_symedit_alias=" + section + ":0,function"
	edited := filepath.Join(dir, "section-edited.obj")
	h.run("symedit-section-objcopy.log", h.root, nil, h.bao, "objcopy", "-wildcard", "-remove-section", ".debug*", "-add-symbol", add, object, edited)
	where, values, debug = sections(edited)
	check(debug == 0 && where["bao_symedit_alias"] == section && values["bao_symedit_alias"] == 0, "objcopy result: alias in %q+%d, %d debug sections", where["bao_symedit_alias"], values["bao_symedit_alias"], debug)
	lib := filepath.Join(dir, "libsection.a")
	h.run("symedit-ar-libsection.a.log", h.root, nil, h.windowsAR, "rcS", lib, object)
	signatures := filepath.Join(dir, "section-signatures.json")
	require(os.WriteFile(signatures, []byte(sectionEditsSignatures), 0o644))
	build := []string{h.bao, "build", "-target", h.target, "-bindings", signatures, "-wildcard"}
	app := filepath.Join(h.dst, "symedit-section-app")
	require(os.Mkdir(app, 0o755))
	h.run("symedit-section-producer.log", h.root, nil, append(build, "-remove-section", lib+"=.debug*", "-add-symbol", lib+"=bao_symedit_alias=@bao_symedit_section:0,function", "-o", filepath.Join(app, "native"), lib)...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-windows-symedit-section\ngo 1.26.0\n"), 0o644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(windowsSectionEditsConsumer), 0o644))
	exe := filepath.Join(h.dst, "symedit-section.exe")
	h.run("symedit-section-build.log", app, h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch}), h.goTool, "build", "-o", exe, ".")
	out, err := h.command("symedit-section-run.log", h.root, nil, h.windowsExecute(exe)...)
	check(err == nil && strings.Contains(string(out), "direct: 7 alias: 7\n"), "Windows section edit consumer failed: %v\n%s", err, out)
	out, err = h.command("symedit-section-negative-producer.log", h.root, nil, append(build, "-remove-section", lib+"="+section, "-o", filepath.Join(h.dst, "symedit-section-negative"), lib)...)
	check(err != nil && strings.Contains(string(out), "cannot remove COFF section "+section), "removing the function's section was not refused: %v\n%s", err, out)
}

const sectionEditsSignatures = `{"schema":1,"abi":"c","functions":[
  {"name":"Direct","symbol":"bao_symedit_section","params":[],"result":"int64"},
  {"name":"Alias","symbol":"bao_symedit_alias","params":[],"result":"int64"}
]}`

const windowsSectionEditsConsumer = `package main

import (
	"fmt"
	"runtime"

	native "bao-windows-symedit-section/native"
)

func main() {
	runtime.LockOSThread()
	direct, alias := native.Direct(), native.Alias()
	native.Shutdown()
	fmt.Println("direct:", direct, "alias:", alias)
}
`

const symbolEditsSignatures = `{"schema":1,"abi":"c","functions":[
  {"name":"Wrapped","symbol":"bao_symedit_wrapped","params":[],"result":"int64"},
  {"name":"Components","symbol":"bao_symedit_components","params":[],"result":"int64"}
]}`

const windowsSymbolEditsConsumer = `package main

import (
	"fmt"
	"runtime"

	native "bao-windows-symedit/native"
)

func main() {
	runtime.LockOSThread()
	wrapped, components := native.Wrapped(), native.Components()
	native.Shutdown()
	fmt.Println("wrapped:", wrapped, "components:", components)
}
`
