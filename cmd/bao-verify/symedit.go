package main

import (
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
	h.results["darwin_symbol_edits"] = map[string]any{"status": "PASS", "checks": "lld-style wrap including a call inside the defining object and __real_ bound to it, wrapped libSystem strlen, private prefixes for two archives vendoring the same symbols with identity-renamed entry points, keep-global wildcard on a partially linked primary archive; negative control without prefixes fails on duplicate symbols"}
}

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
