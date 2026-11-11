package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (h *harness) windows() {
	h.env["RUSTUP_TOOLCHAIN"] = "1.99.1"
	arch := strings.TrimPrefix(h.target, "windows/")
	check(arch == "amd64" || arch == "arm64", "Windows suite requires windows/amd64 or windows/arm64")
	if h.windowsRunner == "" {
		check(runtime.GOOS == "windows" && runtime.GOARCH == arch, "native Windows gate requires a matching Windows host; use -windows-runner only for labeled local Wine checks")
		h.results["execution"] = "native Windows " + arch
	} else {
		h.results["execution"] = "local Windows-compatible runner (Wine); native Windows not verified"
	}
	h.results["target"], h.results["profile"] = h.target, "Windows COFF; dynamic CRT lifecycle, compiler TLS and native C++ exceptions; GNU Rust std checked separately in the static suite"
	check(h.windowsDriver == "clang" || h.windowsDriver == "clang-cl" || h.windowsDriver == "msvc" || h.windowsDriver == "mingw", "unknown Windows compiler driver")
	versionFlag := "--version"
	if h.windowsDriver == "msvc" {
		versionFlag = "/?"
	}
	h.run("windows-compiler.log", h.root, nil, h.windowsCC, versionFlag)
	h.results["compiler"] = string(read(filepath.Join(h.dst, "windows-compiler.log")))
	h.results["compiler_driver"] = h.windowsDriver
	if h.windowsDriver == "mingw" {
		machine := string(h.run("windows-mingw-machine.log", h.root, nil, h.windowsCC, "-dumpmachine"))
		check(strings.Contains(machine, "x86_64") && strings.Contains(machine, "mingw"), "requires an actual x64 MinGW-w64 GCC producer")
		obj := filepath.Join(h.dst, "mingw32.obj")
		args := h.windowsCompile(h.windowsCC, filepath.Join(h.root, "examples/windows_runtime/native.c"), obj, "amd64", false)
		args = append(args, "-m32")
		h.run("windows-mingw32-compile.log", h.root, nil, args...)
		outPath := filepath.Join(h.dst, "unsupported-mingw32")
		out, err := h.command("windows-mingw32-reject.log", h.root, nil, h.bao, "build", "-symbol", "bao_windows_run", "-o", outPath, obj)
		check(err != nil && strings.Contains(string(out), "Windows/386 COFF is unsupported"), "32-bit MinGW boundary changed: %v %s", err, out)
		_, err = os.Stat(outPath)
		check(os.IsNotExist(err), "unsupported MinGW32 output was published")
		h.results["mingw32"] = "real GCC -m32 COFF object explicitly rejected; Windows/386 is unsupported"
	}
	h.results["rust"] = string(h.run("windows-rust.log", h.root, nil, "rustc", "--version"))
	check(strings.Contains(h.results["rust"].(string), "rustc 1.99.1 "), "requires Rust 1.99.1")
	triple, rustTarget := "x86_64-w64-windows-gnu", "x86_64-pc-windows-gnu"
	if arch == "arm64" {
		triple, rustTarget = "aarch64-w64-windows-gnu", "aarch64-pc-windows-gnullvm"
	}
	_ = triple
	objects := []string{}
	for _, c := range []struct{ name, path, tool, standard string }{{"runtime", "examples/windows_runtime/native.c", h.windowsCC, "-std=c11"}, {"cpp", "examples/windows_runtime/native.cpp", h.windowsCXX, "-std=c++20"}, {"scalars", "testdata/bindings_integration.c", h.windowsCC, "-std=c11"}} {
		obj := filepath.Join(h.dst, c.name+".obj")
		args := h.windowsCompile(c.tool, filepath.Join(h.root, c.path), obj, arch, c.standard == "-std=c++20")
		h.run("windows-"+c.name+"-compile.log", h.root, nil, args...)
		objects = append(objects, obj)
	}
	archive := filepath.Join(h.dst, "library.a")
	h.run("windows-archive.log", h.root, nil, append([]string{h.windowsAR, "rcS", archive}, objects...)...)
	archiveHash := digest(archive)
	symbols := append([]string{"bao_windows_run", "bao_windows_cpp_run"}, scalarBindingSymbols[1:]...)
	modes := []string{"dwarf", "manifest", "runtime"}
	if h.windowsDriver == "msvc" || h.windowsDriver == "clang-cl" {
		modes = []string{"manifest", "runtime"}
	}
	for _, mode := range modes {
		app := filepath.Join(h.dst, mode)
		require(os.Mkdir(app, 0755))
		args := []string{h.bao, "build", "-target", h.target, "-o", filepath.Join(app, "native")}
		if mode == "manifest" {
			args = append(args, "-bindings", filepath.Join(h.root, "examples/windows_runtime/signatures.json"))
		} else if mode == "dwarf" {
			args = append(args, "-bindings", "dwarf")
		}
		for _, s := range symbols {
			args = append(args, "-symbol", s)
		}
		args = append(args, archive)
		h.run("windows-"+mode+"-producer.log", h.root, nil, args...)
		if mode == "runtime" {
			h.module(app, "bao-bindings-check", "")
		} else {
			require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-bindings-check\ngo 1.26.0\n"), 0644))
		}
		source := windowsConsumer(mode)
		require(os.WriteFile(filepath.Join(app, "main.go"), []byte(source), 0644))
		exe := filepath.Join(h.dst, mode+".exe")
		cross := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch})
		h.run("windows-"+mode+"-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
		checkWindowsFunctionTable(exe, arch)
		deps := string(h.run("windows-"+mode+"-deps.log", app, cross, h.goTool, "list", "-deps", "."))
		check(strings.Contains(deps, puregoModule) == (mode == "runtime"), "Windows binding dependencies mismatch")
		for _, procs := range []string{"1", "4"} {
			out := h.run("windows-"+mode+"-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
			check(strings.Contains(string(out), "PASS: Windows"), "Windows consumer failed")
		}
		if mode != "runtime" && h.windowsDriver == "clang" {
			h.checkWindowsCgo(app, mode, arch, "bao-bindings-check", "PASS: Windows")
		}
		if mode == modes[0] {
			for _, kind := range []string{"constructors", "unwind"} {
				negative := filepath.Join(h.dst, "negative-"+kind)
				copyTree(app, negative)
				path := filepath.Join(negative, "native/symbols_windows_"+arch+".go")
				code := string(read(path))
				if kind == "constructors" {
					check(strings.Contains(code, "callConstructor(p)"), "no constructors to disable")
					code = strings.Replace(code, "callConstructor(p)", "callConstructor=func(uintptr){};callConstructor(p)", 1)
					require(os.WriteFile(path, []byte(code), 0644))
				} else if arch == "arm64" {
					check(strings.Contains(code, "registerFunctionTable(unwindAddress"), "no dynamic function table to disable")
					code = strings.Replace(code, "registerFunctionTable(unwindAddress", "registerFunctionTable=func(uintptr,uintptr,uintptr){};registerFunctionTable(unwindAddress", 1)
					require(os.WriteFile(path, []byte(code), 0644))
				} else {
					entries, err := os.ReadDir(filepath.Join(negative, "native"))
					require(err)
					changed := 0
					for _, entry := range entries {
						if !strings.HasSuffix(entry.Name(), ".syso") {
							continue
						}
						path := filepath.Join(negative, "native", entry.Name())
						data := read(path)
						for si := 0; si < int(binary.LittleEndian.Uint16(data[2:])); si++ {
							header := data[20+40*si : 20+40*(si+1)]
							if strings.TrimRight(string(header[:8]), "\x00") == ".pdata" {
								copy(header[:8], []byte(".bao.pd\x00"))
								changed++
							}
						}
						require(os.WriteFile(path, data, 0644))
					}
					check(changed > 0, "no static PE exception tables to disable")
				}
				negativeExe := filepath.Join(h.dst, "negative-"+kind+".exe")
				h.run("windows-negative-"+kind+"-build.log", negative, cross, h.goTool, "build", "-o", negativeExe, ".")
				out, err := h.command("windows-negative-"+kind+"-run.log", h.root, nil, h.windowsExecute(negativeExe)...)
				check(err != nil && strings.Contains(string(out), "native Windows result") && !strings.Contains(string(out), "PASS:"), "Windows %s control did not fail: %v %s", kind, err, out)
			}
		}
	}
	check(digest(archive) == archiveHash, "Windows inference modified original archive")
	h.windowsRust(arch)
	h.windowsLifecycle(arch)
	h.results["windows"] = map[string]any{"status": "CHECKED_WITH_LIMITATIONS", "archive_sha256": archiveHash, "bindings": "manifest and DWARF typed scalar ABI; runtime registration integers", "rust_target": rustTarget, "rust": "Cargo no_std staticlib, Win32 import and actual atomic RAII drop", "unwind": "typed C++ throw/catch/rethrow through RAII frames plus native lookup and negative controls"}
	h.results["status"] = "CHECKED_WITH_LIMITATIONS"
	fmt.Println("PASS: checked Windows CRT/TLS/exception/lifecycle profile; explicit shutdown and runtime DLL requirements retained")
}

func (h *harness) checkWindowsCgo(app, mode, arch, module, marker string) {
	exe := filepath.Join(h.dst, mode+"-cgo.exe")
	env := map[string]string{"CGO_ENABLED": "1", "GOOS": "windows", "GOARCH": arch, "CC": h.windowsCC, "CXX": h.windowsCXX}
	// Windows packages never import runtime/cgo, so Go links internally by default.
	h.run("windows-"+mode+"-cgo-no-dependency-build.log", app, env, h.goTool, "build", "-o", exe, ".")
	out := h.run("windows-"+mode+"-cgo-no-dependency-run.log", h.root, nil, h.windowsExecute(exe)...)
	check(strings.Contains(string(out), marker), "Windows cgo-enabled consumer without cgo dependency failed")
	dep := filepath.Join(app, "cgodep")
	require(os.Mkdir(dep, 0755))
	require(os.WriteFile(filepath.Join(dep, "cgo.go"), []byte("package cgodep\n/* static int answer(void) { return 42; } */\nimport \"C\"\nfunc Answer() int { return int(C.answer()) }\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "cgo_check.go"), []byte(fmt.Sprintf("//go:build cgo\n\npackage main\nimport %q\nfunc init() { if cgodep.Answer() != 42 { panic(\"cgo dependency\") } }\n", module+"/cgodep")), 0644))
	h.run("windows-"+mode+"-cgo-build.log", app, env, h.goTool, "build", "-ldflags=-linkmode=internal", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		out := h.run("windows-"+mode+"-cgo-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
		check(strings.Contains(string(out), marker), "Windows cgo consumer failed")
	}
}

func (h *harness) windowsRust(arch string) {
	// The independent Rust archive exercises real Cargo staticlib member selection.
	rustApp := filepath.Join(h.dst, "rust")
	require(os.Mkdir(rustApp, 0755))
	h.run("windows-rust-producer.log", h.root, nil, h.bao, "build", "-target", h.target, "-manifest-path", filepath.Join(h.root, "examples/windows_runtime/Cargo.toml"), "-offline", "-locked", "-bindings", filepath.Join(h.root, "examples/windows_runtime/rust-signatures.json"), "-symbol", "bao_windows_rust_run", "-o", filepath.Join(rustApp, "native"))
	require(os.WriteFile(filepath.Join(rustApp, "go.mod"), []byte("module bao-windows-rust\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(rustApp, "main.go"), []byte("package main\nimport(\"fmt\";\"bao-windows-rust/native\")\nfunc main(){if native.BaoWindowsRustRun(41)!=42{panic(\"Rust no_std Windows\")};fmt.Println(\"PASS: Windows Rust no_std/Win32/RAII\")}\n"), 0644))
	rustExe := filepath.Join(h.dst, "rust.exe")
	h.run("windows-rust-build.log", rustApp, h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch}), h.goTool, "build", "-o", rustExe, ".")
	checkWindowsFunctionTable(rustExe, arch)
	for _, procs := range []string{"1", "4"} {
		out := h.run("windows-rust-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(rustExe)...)
		check(strings.Contains(string(out), "PASS: Windows Rust"), "Windows Rust execution failed")
	}
}

func (h *harness) windowsCompile(tool, input, output, arch string, cpp bool) []string {
	if h.windowsDriver == "msvc" || h.windowsDriver == "clang-cl" {
		args := []string{tool, "/nologo", "/c", "/O2", "/Z7", "/Zl", "/GS-"}
		if h.windowsDriver == "msvc" && arch == "arm64" {
			// VS 17.14+ outlines atomics by default, requiring a CRT helper.
			// This explicitly bounded no-CRT fixture uses the inline LL/SC form.
			args = append(args, "/forceInterlockedFunctions-")
		}
		if h.windowsDriver == "clang-cl" {
			triple := "x86_64-pc-windows-msvc"
			if arch == "arm64" {
				triple = "aarch64-pc-windows-msvc"
			}
			args = append(args, "--driver-mode=cl", "--target="+triple, "/clang:-ffreestanding", "/clang:-funwind-tables")
		}
		if cpp {
			args = append(args, "/std:c++20", "/EHsc", "/GR-")
		} else {
			args = append(args, "/std:c11")
		}
		if h.windowsDriver == "clang-cl" {
			return append(args, "/Fo"+output, "--", input)
		}
		return append(args, input, "/Fo"+output)
	}
	args := []string{tool, "-O2", "-g", "-ffreestanding", "-funwind-tables", "-fno-omit-frame-pointer"}
	if h.windowsDriver == "clang" {
		triple := "x86_64-w64-windows-gnu"
		if arch == "arm64" {
			triple = "aarch64-w64-windows-gnu"
		}
		args = append(args, "--target="+triple)
	} else {
		check(arch == "amd64", "the MinGW GCC leg requires an amd64 target compiler")
	}
	if cpp {
		args = append(args, "-std=c++20")
	} else {
		args = append(args, "-std=c11")
	}
	return append(args, "-c", input, "-o", output)
}

func (h *harness) windowsExecute(exe string) []string {
	if h.windowsRunner != "" {
		return []string{h.windowsRunner, exe}
	}
	return []string{exe}
}
func (h *harness) windowsInferArgs(archive string, symbols []string) []string {
	args := []string{h.bao, "bindings"}
	for _, s := range symbols {
		args = append(args, "-symbol", s)
	}
	return append(args, archive)
}
func windowsConsumer(mode string) string {
	if mode == "runtime" {
		return `package main
import("fmt";"bao-bindings-check/native";"github.com/ebitengine/purego")
func main(){var run func(uint64)uint64;var cpp func()uint64;purego.RegisterFunc(&run,native.SymbolAddr0());purego.RegisterFunc(&cpp,native.SymbolAddr1());if run(41)!=42||cpp()!=42{panic("native Windows result")};fmt.Println("PASS: Windows runtime registration imports/construction/C++ scope cleanup")}
`
	}
	return `package main
import("fmt";"runtime";"sync/atomic";"unsafe";"bao-bindings-check/native")
func main(){
 if native.BaoWindowsRun(41)!=42||native.BaoWindowsCppRun()!=42{panic("native Windows result")}
 if native.BaoScalarInts(1,-2,3,-4,5,-6,7,-8,9,-10)!=-55{panic("integers")}
 if native.BaoScalarFloats(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18)!=2109{panic("floats")}
 if native.BaoScalarMixed(-1,2,3,4,5,6,7,8,9,10,11,12)!=76{panic("mixed")}
 if native.BaoScalarNarrow(-1,2,-3,4,-5,6,-7,8,-9,10,-123,456,-789,1011)!=560{panic("narrow")}
 if native.BaoScalarU32(0xf1234567)!=0xf1234567{panic("u32")}
 x:=uint64(41);if native.BaoScalarPointer(unsafe.Pointer(&x))!=unsafe.Pointer(&x)||x!=42{panic("pointer")}
 var started uint32;var ran atomic.Bool;done:=make(chan struct{})
 go func(){for atomic.LoadUint32(&started)==0{runtime.Gosched()};ran.Store(true);close(done)}()
 if native.BaoScalarWait(50000,unsafe.Pointer(&started))!=42||!ran.Load(){panic("scheduler")};<-done
 fmt.Println("PASS: Windows typed scalar ABI/FP/mixed/spills/pointers/scheduler; constructor/native unwind lookup/C++ scope cleanup")
}
`
}
