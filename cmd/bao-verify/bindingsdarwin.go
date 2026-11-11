package main

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var bindingExports = []string{"bao_scalar_tls_next", "bao_scalar_ints", "bao_scalar_floats", "bao_scalar_mixed", "bao_scalar_narrow", "bao_scalar_pointer", "bao_scalar_wait", "bao_scalar_u32"}

func (h *harness) bindingsDarwin() {
	check(runtime.GOOS == "darwin" && (h.target == "darwin/arm64" || h.target == "darwin/amd64"), "bindings Darwin suite requires macOS")
	arch := strings.TrimPrefix(h.target, "darwin/")
	clangTarget := "arm64-apple-macos11"
	if arch == "amd64" {
		clangTarget = "x86_64-apple-macos11"
	}
	h.env["GOOS"] = "darwin"
	h.env["GOARCH"] = arch
	obj := filepath.Join(h.dst, "optimized-debug.o")
	h.run("bindings-c-compile.log", h.root, nil, "/usr/bin/clang", "-target", clangTarget, "-O2", "-g", "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer", "-c", filepath.Join(h.root, "testdata/bindings_integration.c"), "-o", obj)
	before := digest(obj)
	args := []string{h.bao, "bindings"}
	for _, s := range bindingExports {
		args = append(args, "-symbol", s)
	}
	args = append(args, obj)
	manifest := h.run("bindings-inference.json", h.root, nil, args...)
	manifestPath := filepath.Join(h.dst, "signatures.json")
	require(os.WriteFile(manifestPath, manifest, 0644))
	results := map[string]any{}
	for _, mode := range []string{"manifest", "dwarf"} {
		app := filepath.Join(h.dst, "bindings-"+mode)
		require(os.Mkdir(app, 0755))
		require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-bindings-check\ngo 1.26.0\n"), 0644))
		copyFile(filepath.Join(h.root, "testdata/bindings_consumer.go.tmpl"), filepath.Join(app, "main.go"))
		binding := manifestPath
		if mode == "dwarf" {
			binding = "dwarf"
		}
		args := []string{h.bao, "translate", "-target", h.target, "-bindings", binding, "-o", filepath.Join(app, "native")}
		if mode == "dwarf" {
			for _, s := range bindingExports {
				args = append(args, "-symbol", s)
			}
		}
		args = append(args, obj)
		h.run("bindings-"+mode+"-producer.log", h.root, nil, args...)
		debug := readJSON(filepath.Join(app, "native/bao-debug.json"))
		check(debug["stripped"] == true && debug["removed_sections"].(float64) > 0, "native DWARF was not stripped after inference")
		entries, err := os.ReadDir(filepath.Join(app, "native"))
		require(err)
		nativeDebugSections := 0
		unwind := 0
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".syso") {
				continue
			}
			f, err := elf.Open(filepath.Join(app, "native", e.Name()))
			require(err)
			for _, s := range f.Sections {
				if strings.Contains(s.Name, "debug_") {
					nativeDebugSections++
				}
				if strings.Contains(s.Name, "eh_frame") || strings.Contains(s.Name, "comp_eh") {
					unwind++
				}
			}
			require(f.Close())
		}
		check(nativeDebugSections == 0 && unwind > 0, "debug stripping removed unwind or retained debug payload")
		exe := filepath.Join(h.dst, "bindings-"+mode+"-executable")
		h.consumer("bindings-"+mode+"-build.log", app, h.goTool, "build", "-o", exe, ".")
		deps := string(h.consumer("bindings-"+mode+"-deps.log", app, h.goTool, "list", "-deps", "."))
		check(!strings.Contains(deps, "ebitengine/purego"), "typed consumer still depends on purego")
		for _, procs := range []string{"1", "4"} {
			check(strings.Contains(string(h.run("bindings-"+mode+"-run-"+procs+".log", app, map[string]string{"GOMAXPROCS": procs}, exe)), "PASS: typed scalars"), "typed native ABI failed")
		}
		h.run("bindings-"+mode+"-sign.log", app, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
		h.run("bindings-"+mode+"-verify.log", app, nil, "codesign", "--verify", "--strict", exe)
		check(strings.Contains(string(h.consumer("bindings-"+mode+"-signed-run.log", app, exe)), "PASS: typed scalars"), "signed typed executable failed")
		h.checkDarwinCgo(app, "bindings-"+mode, "PASS: typed scalars")
		results[mode] = map[string]any{"status": "PASS", "native_debug_sections": nativeDebugSections, "unwind_sections": unwind, "removed_sections": debug["removed_sections"], "executable_sha256": digest(exe)}
	}
	check(digest(obj) == before, "producer modified optimized debug input")
	// Exercise the Cargo producer's optimized full-debug path, then retain native
	// panic/TLS semantics after Bao removes the debug payloads.
	rustApp := filepath.Join(h.dst, "bindings-rust-runtime")
	require(os.Mkdir(rustApp, 0755))
	require(os.WriteFile(filepath.Join(rustApp, "go.mod"), []byte("module bao-bindings-check\ngo 1.26.0\n"), 0644))
	h.run("bindings-rust-producer.log", h.root, nil, h.bao, "build", "-target", h.target, "-manifest-path", filepath.Join(h.root, "examples/rust_runtime/Cargo.toml"), "-offline", "-locked", "-bindings", "dwarf", "-symbol", "bao_example_run", "-symbol", "bao_example_check_finalized", "-o", filepath.Join(rustApp, "native"))
	require(os.WriteFile(filepath.Join(rustApp, "main.go"), []byte(`package main
import("fmt";"runtime";"bao-bindings-check/native")
func main(){runtime.LockOSThread();if native.BaoExampleRun()!=42{panic("native run")};native.TLSFinalizeCurrentThread();if native.BaoExampleCheckFinalized()!=42||native.TLSLiveBlocks()!=0||native.TLSDestroyedBlocks()!=9{panic("TLS teardown")};fmt.Println("PASS: typed DWARF-inferred Rust std panic/RAII/8 threads/9 TLS drops; debug stripped; no purego module")}
`), 0644))
	rustDebug := readJSON(filepath.Join(rustApp, "native/bao-debug.json"))
	check(rustDebug["removed_sections"].(float64)+rustDebug["removed_symbols"].(float64) > 0, "Rust debug payload/symbols were not stripped")
	rustExe := filepath.Join(h.dst, "bindings-rust-executable")
	h.consumer("bindings-rust-build.log", rustApp, h.goTool, "build", "-o", rustExe, ".")
	check(!strings.Contains(string(h.consumer("bindings-rust-deps.log", rustApp, h.goTool, "list", "-deps", ".")), "ebitengine/purego"), "Rust static binding still depends on purego")
	for _, procs := range []string{"1", "4"} {
		check(strings.Contains(string(h.run("bindings-rust-run-"+procs+".log", rustApp, map[string]string{"GOMAXPROCS": procs}, rustExe)), "PASS: typed DWARF-inferred Rust std"), "typed Rust runtime execution failed")
	}
	h.run("bindings-rust-sign.log", rustApp, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", rustExe)
	h.run("bindings-rust-verify.log", rustApp, nil, "codesign", "--verify", "--strict", rustExe)
	check(strings.Contains(string(h.consumer("bindings-rust-signed-run.log", rustApp, rustExe)), "PASS: typed DWARF-inferred Rust std"), "signed typed Rust executable failed")
	h.checkDarwinCgo(rustApp, "bindings-rust", "PASS: typed DWARF-inferred Rust std")
	negative := filepath.Join(h.dst, "bindings-rust-negative")
	copyTree(rustApp, negative)
	goPath := filepath.Join(negative, "native/symbols_darwin_"+arch+".go")
	source := string(read(goPath))
	check(strings.Contains(source, "registerFrame("), "missing Rust registration to disable")
	source = strings.Replace(source, "registerFrame(", "registerFrame = func(uintptr){}\n registerFrame(", 1)
	require(os.WriteFile(goPath, []byte(source), 0644))
	negExe := filepath.Join(h.dst, "bindings-rust-negative-executable")
	h.consumer("bindings-rust-negative-build.log", negative, h.goTool, "build", "-o", negExe, ".")
	out, err := h.command("bindings-rust-negative-run.log", negative, nil, negExe)
	check(err != nil && strings.Contains(string(out), "failed to initiate panic") && !strings.Contains(string(out), "PASS:"), "typed Rust unwind negative control failed")
	results["optimized_rust_std"] = map[string]any{"status": "PASS", "removed_debug_sections": rustDebug["removed_sections"], "runtime": "panic caught; 2 RAII drops; 8 native threads; 9 TLS drops, live=0 freed=9", "negative_unwind": "PASS", "executable_sha256": digest(rustExe)}
	h.results["typed_bindings"] = map[string]any{"status": "PASS", "target": h.target, "modes": results, "producer": "optimized -O2 -g C; inferred scalar signatures before native debug stripping", "consumer": "stock Go CGO_ENABLED=0; CGO_ENABLED=1 with default flags; CGO_ENABLED=1 with internal linking and a cgo dependency; GOPROXY=off", "runtime": "integer/FP register and stack args; mixed/narrow types; uint32; pointer result/lifetime; TLS; scheduler progress while C blocks", "bootstrap": "bundled adapted Apache/BSD fakecgo installed from runtime._cgo_init unless runtime/cgo is linked"}
	fmt.Println("PASS typed bindings", h.target)
}

// Exercise cgo-enabled builds. Without another cgo dependency runtime/cgo is
// not linked and Go links internally by default. A real cgo dependency links
// runtime/cgo, whose default external link cannot consume Darwin's ELF
// containers, so it requires Go internal linking.
func (h *harness) checkDarwinCgo(app, name, marker string) {
	env := map[string]string{"CGO_ENABLED": "1", "CC": "/usr/bin/clang", "CXX": "/usr/bin/clang++"}
	exe := filepath.Join(h.dst, name+"-cgo-executable")
	h.run(name+"-cgo-no-dependency-build.log", app, env, h.goTool, "build", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		check(strings.Contains(string(h.run(name+"-cgo-no-dependency-run-"+procs+".log", app, map[string]string{"GOMAXPROCS": procs}, exe)), marker), "cgo-enabled native ABI without cgo dependency failed")
	}
	dep := filepath.Join(app, "cgodep")
	require(os.Mkdir(dep, 0755))
	require(os.WriteFile(filepath.Join(dep, "cgo.go"), []byte("package cgodep\n/* static int answer(void) { return 42; } */\nimport \"C\"\nfunc Answer() int { return int(C.answer()) }\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "cgo_check.go"), []byte("//go:build cgo\n\npackage main\nimport \"bao-bindings-check/cgodep\"\nfunc init() { if cgodep.Answer() != 42 { panic(\"cgo dependency\") } }\n"), 0644))
	_, err := h.command(name+"-cgo-default-link-negative.log", app, env, h.goTool, "build", "-o", filepath.Join(h.dst, name+"-not-produced"), ".")
	check(err != nil, "cgo dependency unexpectedly linked with the default external linker")
	h.run(name+"-cgo-build.log", app, env, h.goTool, "build", "-ldflags=-linkmode=internal", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		check(strings.Contains(string(h.run(name+"-cgo-run-"+procs+".log", app, map[string]string{"GOMAXPROCS": procs}, exe)), marker), "cgo native ABI failed")
	}
}
